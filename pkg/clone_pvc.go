/*
Copyright AppsCode Inc. and Contributors

Licensed under the AppsCode Community License 1.0.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://github.com/appscode/licenses/raw/1.0.0/AppsCode-Community-1.0.0.md

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package pkg

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"gomodules.xyz/flags"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"
	kmapi "kmodules.xyz/client-go/api/v1"
	kmc "kmodules.xyz/client-go/client"
	"kubestash.dev/apimachinery/apis"
	coreapi "kubestash.dev/apimachinery/apis/core/v1alpha1"
	storageapi "kubestash.dev/apimachinery/apis/storage/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type storageOption struct {
	provider         string
	bucket           string
	prefix           string
	storageSecret    string
	encryptSecret    string
	encryptNamespace string
	endpoint         string
	region           string
	maxConnections   int64
	timeConst        string

	storage *storageapi.BackupStorage
	pvc     *corev1.PersistentVolumeClaim
}

func NewCmdClonePVC() *cobra.Command {
	var storageName, storageNamespace string
	storageOpt := storageOption{}
	cmd := &cobra.Command{
		Use:               "pvc",
		Short:             `Clone PVC`,
		Long:              `Clone PVC using backup and restore process`,
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags.EnsureRequiredFlags(cmd, "encrypt-secret", "encrypt-secret-namespace")
			if storageName == "" {
				flags.EnsureRequiredFlags(cmd, "provider", "bucket")
			}
			if storageOpt.provider == string(storageapi.ProviderS3) {
				flags.EnsureRequiredFlags(cmd, "endpoint")
			}

			pvcName := args[0]

			var err error
			storageOpt.pvc, err = getPVC(kmapi.ObjectReference{
				Name:      pvcName,
				Namespace: srcNamespace,
			})
			if err != nil {
				return err
			}
			klog.Infof("Start cloning PVC %s/%s to namespace %s.", storageOpt.pvc.Namespace, storageOpt.pvc.Name, dstNamespace)

			storageOpt.timeConst = fmt.Sprintf("%d", time.Now().Unix())

			if storageName == "" {
				storageOpt.storage = storageOpt.newStorage()
				klog.Infof("Creating BackupStorage %s/%s.", storageOpt.storage.Namespace, storageOpt.storage.Name)
				if err = storageOpt.createStorage(); err != nil {
					return err
				}
				if err = storageOpt.waitUntilBackupStorageIsReady(); err != nil {
					return err
				}
				klog.Infof("BackupStorage %s/%s has been created successfully.", storageOpt.storage.Namespace, storageOpt.storage.Name)

				defer func() {
					if err = klient.Delete(context.Background(), storageOpt.storage); err != nil {
						klog.Errorf("Failed to delete BackupStorage %s/%s. Reason: %v", storageOpt.storage.Namespace, storageOpt.storage.Name, err)
						return
					}
					klog.Infof("BackupStorage %s/%s has been deleted successfully.", storageOpt.storage.Namespace, storageOpt.storage.Name)
				}()
			} else {
				storageOpt.storage, err = getBackupStorage(kmapi.ObjectReference{
					Name:      storageName,
					Namespace: storageNamespace,
				})
				if err != nil {
					return err
				}
			}

			if err = storageOpt.backupPVC(); err != nil {
				return err
			}
			klog.Infof("PVC %s/%s has been successfully taken backup.", storageOpt.pvc.Namespace, storageOpt.pvc.Name)

			if err = storageOpt.restorePVC(); err != nil {
				return err
			}
			klog.Infof("PVC %s/%s is cloned to namespace %s successfully.", storageOpt.pvc.Namespace, storageOpt.pvc.Name, dstNamespace)

			return nil
		},
	}
	cmd.Flags().StringVar(&storageOpt.provider, "provider", storageOpt.provider, "Backend provider (i.e. gcs, s3, azure etc)")
	cmd.Flags().StringVar(&storageOpt.bucket, "bucket", storageOpt.bucket, "Name of the cloud bucket/container")
	cmd.Flags().StringVar(&storageOpt.endpoint, "endpoint", storageOpt.endpoint, "Endpoint for s3 or s3 compatible backend")
	cmd.Flags().StringVar(&storageOpt.region, "region", storageOpt.region, "Region for s3 or s3 compatible backend")
	cmd.Flags().Int64Var(&storageOpt.maxConnections, "max-connections", storageOpt.maxConnections, "Maximum concurrent connections for GCS, Azure and B2 backend")
	cmd.Flags().StringVar(&storageOpt.storageSecret, "storage-secret", storageOpt.storageSecret, "Name of the Storage Secret")
	cmd.Flags().StringVar(&storageOpt.encryptSecret, "encrypt-secret", storageOpt.encryptSecret, "Name of the Encryption Secret")
	cmd.Flags().StringVar(&storageOpt.encryptNamespace, "encrypt-secret-namespace", "default", "Namespace of the Encryption Secret")
	cmd.Flags().StringVar(&storageOpt.prefix, "prefix", storageOpt.prefix, "Directory inside the backend")

	cmd.Flags().StringVar(&storageName, "storage-name", storageName, "Name of the BackupStorage")
	cmd.Flags().StringVar(&storageNamespace, "storage-namespace", "default", "Namespace of the BackupStorage")

	return cmd
}

func (opt *storageOption) newStorage() *storageapi.BackupStorage {
	fromAllNameSpace := apis.NamespacesFromAll
	storage := &storageapi.BackupStorage{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%s-%s", opt.provider, "storage", opt.timeConst),
			Namespace: srcNamespace,
		},
		Spec: storageapi.BackupStorageSpec{
			Storage: opt.getBackendInfo(),
			UsagePolicy: &apis.UsagePolicy{
				AllowedNamespaces: apis.AllowedNamespaces{
					From: &fromAllNameSpace,
				},
			},
			Default:        false,
			DeletionPolicy: storageapi.DeletionPolicyWipeOut,
		},
	}
	return storage
}

func (opt *storageOption) getBackendInfo() storageapi.Backend {
	var backend storageapi.Backend
	switch opt.provider {
	case string(storageapi.ProviderGCS):
		backend = storageapi.Backend{
			Provider: storageapi.ProviderGCS,
			GCS: &storageapi.GCSSpec{
				Bucket:         opt.bucket,
				Prefix:         opt.prefix,
				MaxConnections: opt.maxConnections,
				Secret:         opt.storageSecret,
			},
		}
	case string(storageapi.ProviderAzure):
		backend = storageapi.Backend{
			Provider: storageapi.ProviderAzure,
			Azure: &storageapi.AzureSpec{
				Container:      opt.bucket,
				Prefix:         opt.prefix,
				MaxConnections: opt.maxConnections,
				Secret:         opt.storageSecret,
			},
		}
	case string(storageapi.ProviderS3):
		backend = storageapi.Backend{
			Provider: storageapi.ProviderS3,
			S3: &storageapi.S3Spec{
				Bucket:   opt.bucket,
				Prefix:   opt.prefix,
				Endpoint: opt.endpoint,
				Region:   opt.region,
				Secret:   opt.storageSecret,
			},
		}
	case string(storageapi.ProviderB2):
		backend = storageapi.Backend{
			Provider: storageapi.ProviderB2,
			B2: &storageapi.B2Spec{
				Bucket:         opt.bucket,
				Prefix:         opt.prefix,
				MaxConnections: opt.maxConnections,
				Secret:         opt.storageSecret,
			},
		}
	case string(storageapi.ProviderSwift):
		backend = storageapi.Backend{
			Provider: storageapi.ProviderSwift,
			Swift: &storageapi.SwiftSpec{
				Container: opt.bucket,
				Prefix:    opt.prefix,
				Secret:    opt.storageSecret,
			},
		}
	}

	return backend
}

func (opt *storageOption) createStorage() error {
	_, err := kmc.CreateOrPatch(
		context.Background(),
		klient,
		opt.storage,
		func(obj client.Object, createOp bool) client.Object {
			in := obj.(*storageapi.BackupStorage)
			in.Spec = opt.storage.Spec
			return in
		},
	)
	return err
}

func (opt *storageOption) waitUntilBackupStorageIsReady() error {
	return wait.PollUntilContextTimeout(context.Background(), PullInterval, WaitTimeOut, true, func(ctx context.Context) (done bool, err error) {
		if err := klient.Get(ctx, client.ObjectKeyFromObject(opt.storage), opt.storage); err != nil {
			return false, nil
		}

		if opt.storage.Status.Phase == storageapi.BackupStorageReady {
			return true, nil
		}

		return false, nil
	})
}

func (opt *storageOption) backupPVC() error {
	retentionPolicy := opt.newRetentionPolicy()
	klog.Infof("Creating RetentionPolicy %s/%s.", retentionPolicy.Namespace, retentionPolicy.Name)
	if err := opt.createRetentionPolicy(retentionPolicy); err != nil {
		return err
	}
	klog.Infof("RetentionPolicy %s/%s has been created successfully.", retentionPolicy.Namespace, retentionPolicy.Name)

	backupConfig := opt.newBackupConfig()
	klog.Infof("Creating BackupConfiguration %s/%s.", backupConfig.Namespace, backupConfig.Name)
	if err := opt.createBackupConfig(backupConfig); err != nil {
		return err
	}
	if err := waitUntilBackupConfigIsReady(backupConfig); err != nil {
		return err
	}
	klog.Infof("BackupConfiguration %s/%s has been created successfully.", backupConfig.Namespace, backupConfig.Name)

	klog.Infof("Triggering BackupSession to backup PVC %s/%s", opt.pvc.Namespace, opt.pvc.Name)
	backupSession, err := triggerBackup(backupConfig, backupConfig.Spec.Sessions[0])
	if err != nil {
		return err
	}
	if err = waitUntilBackupSessionCompleted(backupSession); err != nil {
		return err
	}
	klog.Infof("BackupSession %s/%s succeeded.", backupSession.Namespace, backupSession.Name)

	// delete backupConfig
	if err = klient.Delete(context.Background(), backupConfig); err != nil {
		return err
	}
	klog.Infof("BackupConfiguration %s/%s has been deleted successfully.", backupConfig.Namespace, backupConfig.Name)

	// delete retentionPolicy
	if err = klient.Delete(context.Background(), retentionPolicy); err != nil {
		return err
	}
	klog.Infof("RetentionPolicy %s/%s has been deleted successfully.", retentionPolicy.Namespace, retentionPolicy.Name)

	return nil
}

func (opt *storageOption) newRetentionPolicy() *storageapi.RetentionPolicy {
	fromAllNameSpace := apis.NamespacesFromSame
	return &storageapi.RetentionPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%s", opt.pvc.Name, "retention-policy"),
			Namespace: srcNamespace,
		},
		Spec: storageapi.RetentionPolicySpec{
			MaxRetentionPeriod: "1d",
			SuccessfulSnapshots: &storageapi.SuccessfulSnapshotsKeepPolicy{
				Last: ptr.To(int32(2)),
			},
			FailedSnapshots: &storageapi.FailedSnapshotsKeepPolicy{
				Last: ptr.To(int32(2)),
			},
			UsagePolicy: &apis.UsagePolicy{
				AllowedNamespaces: apis.AllowedNamespaces{
					From: &fromAllNameSpace,
				},
			},
			Default: false,
		},
	}
}

func (opt *storageOption) createRetentionPolicy(rp *storageapi.RetentionPolicy) error {
	_, err := kmc.CreateOrPatch(
		context.Background(),
		klient,
		rp,
		func(obj client.Object, createOp bool) client.Object {
			in := obj.(*storageapi.RetentionPolicy)
			in.Spec = rp.Spec
			return in
		},
	)
	return err
}

func (opt *storageOption) newBackupConfig() *coreapi.BackupConfiguration {
	return &coreapi.BackupConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%s", opt.pvc.Name, "backup"),
			Namespace: srcNamespace,
		},
		Spec: coreapi.BackupConfigurationSpec{
			Target: &kmapi.TypedObjectReference{
				Kind:      apis.KindPersistentVolumeClaim,
				Name:      opt.pvc.Name,
				Namespace: srcNamespace,
			},
			Backends: []coreapi.BackendReference{
				{
					Name: opt.storage.Name,
					StorageRef: &kmapi.ObjectReference{
						Name:      opt.storage.Name,
						Namespace: opt.storage.Namespace,
					},
					RetentionPolicy: &kmapi.ObjectReference{
						Name:      fmt.Sprintf("%s-%s", opt.pvc.Name, "retention-policy"),
						Namespace: srcNamespace,
					},
				},
			},
			Sessions: []coreapi.Session{
				{
					SessionConfig: &coreapi.SessionConfig{
						Name: "pvc-session",
						Scheduler: &coreapi.SchedulerSpec{
							Schedule: PVCSchedule,
							JobTemplate: coreapi.JobTemplate{
								BackoffLimit: ptr.To(int32(1)),
							},
						},
						RetryConfig: &coreapi.RetryConfig{
							MaxRetry: 2,
							Delay: metav1.Duration{
								Duration: time.Minute * 1,
							},
						},
					},
					Repositories: []coreapi.RepositoryInfo{
						{
							Name:      fmt.Sprintf("%s-%s-%s", opt.storage.Spec.Storage.Provider, "repo", opt.timeConst),
							Backend:   opt.storage.Name,
							Directory: filepath.Join("pvc", opt.pvc.Name),
							EncryptionSecret: &kmapi.ObjectReference{
								Name:      opt.encryptSecret,
								Namespace: opt.encryptNamespace,
							},
							DeletionPolicy: storageapi.DeletionPolicyWipeOut,
						},
					},
					Addon: &coreapi.AddonInfo{
						Name: PVCAddon,
						Tasks: []coreapi.TaskReference{
							{
								Name: PVCBackupTask,
							},
						},
					},
				},
			},
		},
	}
}

func (opt *storageOption) createBackupConfig(bc *coreapi.BackupConfiguration) error {
	_, err := kmc.CreateOrPatch(
		context.Background(),
		klient,
		bc,
		func(obj client.Object, createOp bool) client.Object {
			in := obj.(*coreapi.BackupConfiguration)
			in.Spec = bc.Spec
			return in
		},
	)
	return err
}

func waitUntilBackupConfigIsReady(bc *coreapi.BackupConfiguration) error {
	return wait.PollUntilContextTimeout(context.Background(), PullInterval, WaitTimeOut, true, func(ctx context.Context) (done bool, err error) {
		if err := klient.Get(ctx, client.ObjectKeyFromObject(bc), bc); err != nil {
			return false, nil
		}

		if bc.Status.Phase == coreapi.BackupInvokerReady {
			return true, nil
		}

		if bc.Status.Phase == coreapi.BackupInvokerInvalid {
			return true, fmt.Errorf("BackupConfiguration is invalid")
		}

		return false, nil
	})
}

func waitUntilBackupSessionCompleted(bs *coreapi.BackupSession) error {
	return wait.PollUntilContextTimeout(context.Background(), PullInterval, WaitTimeOut, true, func(ctx context.Context) (done bool, err error) {
		if err := klient.Get(ctx, client.ObjectKeyFromObject(bs), bs); err != nil {
			return false, nil
		}

		if bs.Status.Phase == coreapi.BackupSessionSucceeded {
			return true, nil
		}
		if bs.Status.Phase == coreapi.BackupSessionFailed {
			return true, fmt.Errorf("BackupSession has been failed")
		}

		return false, nil
	})
}

func (opt *storageOption) restorePVC() error {
	if err := opt.createPVC(); err != nil {
		return err
	}
	klog.Infof("PVC %s/%s has been created successfully.", dstNamespace, opt.pvc.Name)

	restoreSession := opt.newRestoreSession()
	klog.Infof("Creating RestoreSession %s/%s.", restoreSession.Namespace, restoreSession.Name)
	if err := opt.createRestoreSession(restoreSession); err != nil {
		return err
	}
	klog.Infof("RestoreSession %s/%s has been created successfully.", restoreSession.Namespace, restoreSession.Name)
	if err := waitUntilRestoreSessionCompleted(restoreSession); err != nil {
		return err
	}
	klog.Infof("RestoreSession %s/%s succeeded.", restoreSession.Namespace, restoreSession.Name)

	if err := klient.Delete(context.Background(), restoreSession); err != nil {
		return err
	}
	klog.Infof("RestoreSession %s/%s has been deleted successfully.", restoreSession.Namespace, restoreSession.Name)

	return nil
}

func (opt *storageOption) createPVC() error {
	newPVC := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      opt.pvc.Name,
			Namespace: dstNamespace,
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes:      opt.pvc.Spec.AccessModes,
			Resources:        opt.pvc.Spec.Resources,
			StorageClassName: opt.pvc.Spec.StorageClassName,
		},
	}

	_, err := kmc.CreateOrPatch(
		context.Background(),
		klient,
		newPVC,
		func(obj client.Object, createOp bool) client.Object {
			in := obj.(*corev1.PersistentVolumeClaim)
			in.Spec = newPVC.Spec
			return in
		},
	)
	return err
}

func (opt *storageOption) newRestoreSession() *coreapi.RestoreSession {
	return &coreapi.RestoreSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      opt.pvc.Name,
			Namespace: srcNamespace,
		},
		Spec: coreapi.RestoreSessionSpec{
			Target: &kmapi.TypedObjectReference{
				Kind:      apis.KindPersistentVolumeClaim,
				Name:      opt.pvc.Name,
				Namespace: dstNamespace,
			},
			DataSource: &coreapi.RestoreDataSource{
				// define a method for getting repo name
				Repository: fmt.Sprintf("%s-%s-%s", opt.storage.Spec.Storage.Provider, "repo", opt.timeConst),
				Snapshot:   LatestSnapshot,
				EncryptionSecret: &kmapi.ObjectReference{
					Name:      opt.encryptSecret,
					Namespace: opt.encryptNamespace,
				},
			},
			Addon: &coreapi.AddonInfo{
				Name: PVCAddon,
				Tasks: []coreapi.TaskReference{
					{
						Name: PVCRestoreTask,
					},
				},
			},
		},
	}
}

func (opt *storageOption) createRestoreSession(rs *coreapi.RestoreSession) error {
	_, err := kmc.CreateOrPatch(
		context.Background(),
		klient,
		rs,
		func(obj client.Object, createOp bool) client.Object {
			in := obj.(*coreapi.RestoreSession)
			in.Spec = rs.Spec
			return in
		},
	)
	return err
}

func waitUntilRestoreSessionCompleted(rs *coreapi.RestoreSession) error {
	return wait.PollUntilContextTimeout(context.Background(), PullInterval, WaitTimeOut, true, func(ctx context.Context) (done bool, err error) {
		if err := klient.Get(ctx, client.ObjectKeyFromObject(rs), rs); err != nil {
			return false, nil
		}

		if rs.Status.Phase == coreapi.RestoreSucceeded {
			return true, nil
		}
		if rs.Status.Phase == coreapi.RestoreFailed {
			return true, fmt.Errorf("RestoreSession has been failed")
		}
		if rs.Status.Phase == coreapi.RestoreInvalid {
			return true, fmt.Errorf("RestoreSession is invalid")
		}

		return false, nil
	})
}
