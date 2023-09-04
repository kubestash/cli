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

package pkg

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"
	"k8s.io/utils/pointer"
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
}

func NewCmdClonePVC() *cobra.Command {
	storageOpt := storageOption{}
	cmd := &cobra.Command{
		Use:               "pvc",
		Short:             `Clone PVC`,
		Long:              `Use Backup and Restore process for cloning PVC`,
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			pvcName := args[0]

			pvc, err := getPVC(pvcName)
			if err != nil {
				return err
			}
			klog.Infof("PVC %s/%s needs to be cloned to namespace %s.", pvc.Namespace, pvc.Name, dstNamespace)

			storageOpt.timeConst = fmt.Sprintf("%d", time.Now().Unix())

			storage := storageOpt.newStorage()
			if err = storageOpt.createStorage(storage); err != nil {
				return err
			}
			if err = waitUntilBackupStorageIsReady(storage); err != nil {
				return err
			}
			klog.Infof("BackupStorage has been created successfully.")

			if err = storageOpt.backupPVC(pvc, storage); err != nil {
				return err
			}
			klog.Infof("PVC has been successfully taken backup.")

			if err = storageOpt.restorePVC(pvc); err != nil {
				return err
			}
			klog.Infof("PVC has been successfully taken restored.")

			if err = klient.Delete(context.Background(), storage); err != nil {
				return err
			}
			klog.Infof("BackupStorage has been deleted successfully.")

			klog.Infof("PVC %s/%s is cloned to namespace %s successfully.", pvc.Namespace, pvc.Name, dstNamespace)

			return nil
		},
	}
	cmd.Flags().StringVar(&storageOpt.provider, "provider", storageOpt.provider, "Backend provider (i.e. gcs, s3, azure etc)")
	cmd.Flags().StringVar(&storageOpt.bucket, "bucket", storageOpt.bucket, "Name of the cloud bucket/container")
	cmd.Flags().StringVar(&storageOpt.endpoint, "endpoint", storageOpt.endpoint, "Endpoint for s3/s3 compatible backend")
	cmd.Flags().StringVar(&storageOpt.region, "region", storageOpt.region, "Region for s3/s3 compatible backend")
	cmd.Flags().Int64Var(&storageOpt.maxConnections, "max-connections", storageOpt.maxConnections, "Specify maximum concurrent connections for GCS, Azure and B2 backend")
	cmd.Flags().StringVar(&storageOpt.storageSecret, "storage-secret", storageOpt.storageSecret, "Name of the Storage Secret")
	cmd.Flags().StringVar(&storageOpt.encryptSecret, "encrypt-secret", storageOpt.encryptSecret, "Name of the Encryption Secret")
	cmd.Flags().StringVar(&storageOpt.encryptNamespace, "encrypt-secret-namespace", storageOpt.encryptNamespace, "Namespace of the Encryption Secret")
	cmd.Flags().StringVar(&storageOpt.prefix, "prefix", storageOpt.prefix, "Prefix denotes the directory inside the backend")

	err := cmd.MarkFlagRequired("provider")
	if err != nil {
		return nil
	}
	err = cmd.MarkFlagRequired("bucket")
	if err != nil {
		return nil
	}
	err = cmd.MarkFlagRequired("storage-secret")
	if err != nil {
		return nil
	}
	err = cmd.MarkFlagRequired("encrypt-secret")
	if err != nil {
		return nil
	}
	err = cmd.MarkFlagRequired("encrypt-secret-namespace")
	if err != nil {
		return nil
	}

	if storageOpt.provider == string(storageapi.ProviderS3) {
		err = cmd.MarkFlagRequired("endpoint")
		if err != nil {
			return nil
		}
	}

	return cmd
}

func getPVC(name string) (*corev1.PersistentVolumeClaim, error) {
	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: srcNamespace,
		},
	}
	if err := klient.Get(context.Background(), client.ObjectKeyFromObject(pvc), pvc); err != nil {
		return nil, err
	}

	return pvc, nil
}

func (opt *storageOption) newStorage() *storageapi.BackupStorage {
	storageName := fmt.Sprintf("%s-%s-%s", opt.provider, "storage", opt.timeConst)
	klog.Infof("Creating Repository: %s to the Namespace: %s", storageName, srcNamespace)
	fromAllNameSpace := apis.NamespacesFromAll
	storage := &storageapi.BackupStorage{
		ObjectMeta: metav1.ObjectMeta{
			Name:      storageName,
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
	case string(storageapi.ProviderRest):
		backend = storageapi.Backend{
			Provider: storageapi.ProviderRest,
			Rest: &storageapi.RestServerSpec{
				URL:    opt.endpoint,
				Secret: opt.storageSecret,
			},
		}
	}

	return backend
}

func (opt *storageOption) createStorage(storage *storageapi.BackupStorage) error {
	_, err := kmc.CreateOrPatch(
		context.Background(),
		klient,
		storage,
		func(obj client.Object, createOp bool) client.Object {
			in := obj.(*storageapi.BackupStorage)
			in.Spec = storage.Spec
			return in
		},
	)
	return err
}

func waitUntilBackupStorageIsReady(storage *storageapi.BackupStorage) error {
	return wait.PollImmediate(PullInterval, WaitTimeOut, func() (done bool, err error) {
		if err := klient.Get(context.Background(), client.ObjectKeyFromObject(storage), storage); err != nil {
			return false, nil
		}

		if storage.Status.Phase == storageapi.BackupStorageReady {
			return true, nil
		}

		return false, nil
	})
}

func (opt *storageOption) backupPVC(pvc *corev1.PersistentVolumeClaim, storage *storageapi.BackupStorage) error {
	retentionPolicy := opt.newRetentionPolicy(pvc.Name)
	klog.Infof("Creating RetentionPolicy: %s to the namespace: %s", retentionPolicy.Name, retentionPolicy.Namespace)
	if err := opt.createRetentionPolicy(retentionPolicy); err != nil {
		return err
	}
	klog.Infof("RetentionPolicy has been created successfully.")

	backupConfig := opt.newBackupConfig(pvc.Name, storage)
	klog.Infof("Creating BackupConfiguration: %s to the namespace: %s", backupConfig.Name, backupConfig.Namespace)
	if err := opt.createBackupConfig(backupConfig); err != nil {
		return err
	}
	if err := waitUntilBackupConfigIsReady(backupConfig); err != nil {
		return err
	}
	klog.Infof("BackupConfiguration has been created successfully.")

	backupSession, err := triggerBackup(backupConfig, backupConfig.Spec.Sessions[0])
	if err != nil {
		return err
	}

	if err = waitUntilBackupSessionCompleted(backupSession); err != nil {
		return err
	}
	klog.Infof("BackupSession has been succeeded.")

	// delete backupConfig
	if err = klient.Delete(context.Background(), backupConfig); err != nil {
		return err
	}
	klog.Infof("BackupConfiguration has been deleted successfully.")

	// delete retentionPolicy
	if err = klient.Delete(context.Background(), retentionPolicy); err != nil {
		return err
	}
	klog.Infof("RetentionPolicy has been deleted successfully.")

	return nil
}

func (opt *storageOption) newRetentionPolicy(pvcName string) *storageapi.RetentionPolicy {
	fromAllNameSpace := apis.NamespacesFromAll
	return &storageapi.RetentionPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%s", pvcName, "retention-policy"),
			Namespace: dstNamespace,
		},
		Spec: storageapi.RetentionPolicySpec{
			MaxRetentionPeriod: "1d",
			SuccessfulSnapshots: &storageapi.SuccessfulSnapshotsKeepPolicy{
				Last: pointer.Int32(2),
			},
			FailedSnapshots: &storageapi.FailedSnapshotsKeepPolicy{
				Last: pointer.Int32(2),
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

func (opt *storageOption) newBackupConfig(pvcName string, storage *storageapi.BackupStorage) *coreapi.BackupConfiguration {
	return &coreapi.BackupConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%s", pvcName, "backup"),
			Namespace: dstNamespace,
		},
		Spec: coreapi.BackupConfigurationSpec{
			Target: &kmapi.TypedObjectReference{
				Kind:      apis.KindPersistentVolumeClaim,
				Name:      pvcName,
				Namespace: srcNamespace,
			},
			Backends: []coreapi.BackendReference{
				{
					Name: storage.Name,
					StorageRef: kmapi.TypedObjectReference{
						APIGroup:  storageapi.GroupVersion.Group,
						Kind:      storageapi.ResourceKindBackupStorage,
						Name:      storage.Name,
						Namespace: storage.Namespace,
					},
					RetentionPolicy: &kmapi.ObjectReference{
						Name:      fmt.Sprintf("%s-%s", pvcName, "retention-policy"),
						Namespace: dstNamespace,
					},
				},
			},
			Sessions: []coreapi.Session{
				{
					SessionConfig: &coreapi.SessionConfig{
						Name: PVCSession,
						Scheduler: &coreapi.SchedulerSpec{
							Schedule: PVCSchedule,
							JobTemplate: coreapi.JobTemplate{
								BackoffLimit: pointer.Int32(1),
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
							Name:      fmt.Sprintf("%s-%s-%s", pvcName, "pvc-storage", opt.timeConst),
							Backend:   storage.Name,
							Directory: filepath.Join("pvc", pvcName),
							EncryptionSecret: &kmapi.ObjectReference{
								Name:      opt.encryptSecret,
								Namespace: opt.encryptNamespace,
							},
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
	return wait.PollImmediate(PullInterval, WaitTimeOut, func() (done bool, err error) {
		if err := klient.Get(context.Background(), client.ObjectKeyFromObject(bc), bc); err != nil {
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
	return wait.PollImmediate(PullInterval, WaitTimeOut, func() (done bool, err error) {
		if err := klient.Get(context.Background(), client.ObjectKeyFromObject(bs), bs); err != nil {
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

func (opt *storageOption) restorePVC(pvc *corev1.PersistentVolumeClaim) error {
	if err := opt.createPVC(pvc); err != nil {
		return err
	}
	klog.Infof("PVC %s/%s has been created successfully.", dstNamespace, pvc.Name)

	restoreSession := opt.newRestoreSession(pvc)
	klog.Infof("Creating RestoreSession: %s to the namespace: %s", restoreSession.Name, restoreSession.Namespace)
	if err := opt.createRestoreSession(restoreSession); err != nil {
		return err
	}
	if err := waitUntilRestoreSessionCompleted(restoreSession); err != nil {
		return err
	}
	klog.Infof("RestoreSession has been created successfully.")

	if err := klient.Delete(context.Background(), restoreSession); err != nil {
		return err
	}
	klog.Infof("RestoreSession has been deleted successfully.")

	return nil
}

func (opt *storageOption) createPVC(pvc *corev1.PersistentVolumeClaim) error {
	newPVC := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      pvc.Name,
			Namespace: dstNamespace,
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes:      pvc.Spec.AccessModes,
			Resources:        pvc.Spec.Resources,
			StorageClassName: pvc.Spec.StorageClassName,
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

func (opt *storageOption) newRestoreSession(pvc *corev1.PersistentVolumeClaim) *coreapi.RestoreSession {
	return &coreapi.RestoreSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      pvc.Name,
			Namespace: dstNamespace,
		},
		Spec: coreapi.RestoreSessionSpec{
			Target: &kmapi.TypedObjectReference{
				Kind:      apis.KindPersistentVolumeClaim,
				Name:      pvc.Name,
				Namespace: dstNamespace,
			},
			DataSource: &coreapi.RestoreDataSource{
				Repository: fmt.Sprintf("%s-%s-%s", pvc.Name, "pvc-storage", opt.timeConst),
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
	return wait.PollImmediate(PullInterval, WaitTimeOut, func() (done bool, err error) {
		if err := klient.Get(context.Background(), client.ObjectKeyFromObject(rs), rs); err != nil {
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
