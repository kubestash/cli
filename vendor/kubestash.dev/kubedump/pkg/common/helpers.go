/*
Copyright AppsCode Inc. and Contributors

Licensed under the AppsCode Free Trial License 1.0.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://github.com/appscode/licenses/raw/1.0.0/AppsCode-Free-Trial-1.0.0.md

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package common

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"kubestash.dev/apimachinery/apis"
	coreapi "kubestash.dev/apimachinery/apis/core/v1alpha1"
	storageapi "kubestash.dev/apimachinery/apis/storage/v1alpha1"
	"kubestash.dev/apimachinery/pkg/restic"

	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/rest"
	restclient "k8s.io/client-go/rest"
	kmapi "kmodules.xyz/client-go/api/v1"
	v1 "kmodules.xyz/offshoot-api/api/v1"
	kubedbapi "kubedb.dev/apimachinery/apis/kubedb/v1alpha2"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
)

func NewRuntimeClient(cfg *restclient.Config) (client.Client, error) {
	scheme := runtime.NewScheme() // for encoding, decoding, converting api objects across different versions
	utilruntime.Must(coreapi.AddToScheme(scheme))
	utilruntime.Must(storageapi.AddToScheme(scheme))
	utilruntime.Must(kubedbapi.AddToScheme(scheme))
	utilruntime.Must(core.AddToScheme(scheme))

	hc, err := rest.HTTPClientFor(cfg)
	if err != nil {
		return nil, err
	}
	mapper, err := apiutil.NewDynamicRESTMapper(cfg, hc)
	if err != nil {
		return nil, err
	}

	return client.New(cfg, client.Options{
		Scheme: scheme,
		Mapper: mapper,
	})
}

func (opt *Options) GetBackupSession() (*coreapi.BackupSession, error) {
	backupSession := &coreapi.BackupSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      opt.BackupSessionName,
			Namespace: opt.Namespace,
		},
	}

	if err := opt.Client.Get(context.Background(), client.ObjectKeyFromObject(backupSession), backupSession); err != nil {
		return nil, err
	}

	return backupSession, nil
}

func (opt *Options) GetRestoreSession() (*coreapi.RestoreSession, error) {
	restoreSession := &coreapi.RestoreSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      opt.RestoreSessionName,
			Namespace: opt.Namespace,
		},
	}

	if err := opt.Client.Get(context.Background(), client.ObjectKeyFromObject(restoreSession), restoreSession); err != nil {
		return nil, err
	}

	return restoreSession, nil
}

func (opt *Options) GetBackupConfiguration() (*coreapi.BackupConfiguration, error) {
	backupConfig := &coreapi.BackupConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name:      opt.BackupSession.Spec.Invoker.Name,
			Namespace: opt.Namespace,
		},
	}

	if err := opt.Client.Get(context.Background(), client.ObjectKeyFromObject(backupConfig), backupConfig); err != nil {
		return nil, err
	}

	return backupConfig, nil
}

func (opt *Options) GetRepository(ref kmapi.ObjectReference) (*storageapi.Repository, error) {
	repo := &storageapi.Repository{}
	if err := opt.Client.Get(context.Background(), ref.ObjectKey(), repo); err != nil {
		return nil, err
	}
	return repo, nil
}

// snapshot related
func (opt *Options) GetSnapshots() ([]storageapi.Snapshot, error) {
	var snapList []storageapi.Snapshot
	for _, s := range opt.BackupSession.Status.Snapshots {
		snap, err := opt.GetSnapshot(kmapi.ObjectReference{
			Name:      s.Name,
			Namespace: opt.Namespace,
		})
		if err != nil {
			return nil, err
		}

		snapList = append(snapList, *snap)
	}

	if len(snapList) == 0 {
		return nil, fmt.Errorf("no snapshot found for backupsession: %s/%s", opt.BackupSession.Namespace, opt.BackupSession.Name)
	}
	return snapList, nil
}

func (opt *Options) GetSnapshot(ref kmapi.ObjectReference) (*storageapi.Snapshot, error) {
	snap := &storageapi.Snapshot{}
	if err := opt.Client.Get(context.Background(), ref.ObjectKey(), snap); err != nil {
		return nil, err
	}
	return snap, nil
}

func (opt *Options) GetResticSnapshotIDs() ([]string, error) {
	if comp, ok := opt.Snapshot.Status.Components[apis.ComponentManifest]; ok {
		var ids []string
		for _, resticStat := range comp.ResticStats {
			ids = append(ids, resticStat.Id)
		}
		if len(ids) == 0 {
			return nil, fmt.Errorf("no restic snapshot id found for component: %s", apis.ComponentManifest)
		}
		return ids, nil
	}

	return nil, fmt.Errorf("component %s not found in snapshot %s/%s", apis.ComponentManifest, opt.Snapshot.Namespace, opt.Snapshot.Name)
}

func (opt *Options) GetResticWrapperForSnapshots(snapshots ...storageapi.Snapshot) (*restic.ResticWrapper, error) {
	if err := opt.setSetupOptionsForSnapshots(snapshots...); err != nil {
		return nil, err
	}
	wrapper, err := restic.NewResticWrapper(&opt.SetupOptions)
	return wrapper, err
}

func (opt *Options) setSetupOptionsForSnapshots(snapshots ...storageapi.Snapshot) error {
	opt.SetupOptions.Client = opt.Client
	opt.SetupOptions.Backends = make([]*restic.Backend, 0, len(snapshots))

	var err error
	opt.SetupOptions.Timeout, err = opt.getTimeout()
	if err != nil {
		return fmt.Errorf("failed to get timeout: %w", err)
	}

	// apply nice, ionice settings from env
	if opt.SetupOptions.Nice == nil {
		opt.SetupOptions.Nice, err = v1.NiceSettingsFromEnv()
		if err != nil {
			return fmt.Errorf("failed to set nice settings: %w", err)
		}
	}

	if opt.SetupOptions.IONice == nil {
		opt.SetupOptions.IONice, err = v1.IONiceSettingsFromEnv()
		if err != nil {
			return fmt.Errorf("failed to set ionice settings: %w", err)
		}
	}

	for _, snap := range snapshots {
		backend := &restic.Backend{}
		repo, err := opt.GetRepository(kmapi.ObjectReference{
			Name:      snap.Spec.Repository,
			Namespace: snap.Namespace,
		})
		if err != nil {
			backend.Error = fmt.Errorf("failed to get repository %s/%s: %w", snap.Namespace, snap.Spec.Repository, err)
		}

		backend.Repository = repo.Name
		backend.BackupStorage = &repo.Spec.StorageRef
		backend.Directory = filepath.Join(repo.Spec.Path, snap.GetComponentPath(apis.ComponentManifest))
		if opt.BackupSession != nil {
			backend.EncryptionSecret = repo.Spec.EncryptionSecret
		} else {
			backend.EncryptionSecret = opt.RestoreSession.Spec.DataSource.EncryptionSecret
		}
		opt.SetupOptions.Backends = append(opt.SetupOptions.Backends, backend)
	}

	return nil
}

func (opt *Options) InitializeRepositories(w *restic.ResticWrapper) {
	var validBackends []*restic.Backend
	for idx, backend := range w.Config.Backends {
		if backend.Error == nil && !w.RepositoryAlreadyExist(backend.Repository) {
			backend.Error = w.InitializeRepository(backend.Repository)
		}

		if backend.Error != nil {
			UpsertSnapshotsComponentStatus(opt.Snapshots[idx:idx+1], nil, nil, backend.Error)
		} else {
			validBackends = append(validBackends, backend)
		}
	}
	w.Config.Backends = validBackends
}

func (opt *Options) getTimeout() (*metav1.Duration, error) {
	var err error
	var timeout *metav1.Duration
	if opt.BackupSession != nil {
		timeout, err = opt.BackupSession.GetRemainingTimeoutDuration()
		if err != nil {
			return nil, err
		}
	} else {
		timeout, err = opt.RestoreSession.GetRemainingTimeoutDuration()
		if err != nil {
			return nil, err
		}
	}
	return timeout, nil
}

func ClearDir(dir string) error {
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	return os.MkdirAll(dir, os.ModePerm)
}
