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
	"time"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
	kmc "kmodules.xyz/client-go/client"
	"kubestash.dev/apimachinery/apis"
	storageapi "kubestash.dev/apimachinery/apis/storage/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type storageOption struct {
	provider       string
	bucket         string
	prefix         string
	secret         string
	endpoint       string
	region         string
	maxConnections int64
	deletionPolicy string
}

func NewCmdClonePVC() *cobra.Command {
	storageOpt := storageOption{}
	cmd := &cobra.Command{
		Use:               "pvc",
		Short:             `Clone PVC`,
		Long:              `Use Backup and Restore process for cloning PVC`,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 || args[0] == "" {
				return fmt.Errorf("PVC name is not found")
			}

			pvcName := args[0]

			pvc, err := getPVC(pvcName)
			if err != nil {
				return err
			}

			// to clone a PVC from source namespace to destination namespace, Steps are following:
			// 1. create BackupStorage to the source namespace.
			// 2. create BackupConfiguration to the destination namespace to take backup of the source PVC.
			// 3. then restore the pvc to the destination namespace.

			storage := storageOpt.newStorage()
			if err = storageOpt.createStorage(storage); err != nil {
				return err
			}
			klog.Infof("BackupStorage has been created successfully.")

			if err = backupPVC(pvc); err != nil {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&storageOpt.provider, "provider", storageOpt.provider, "Backend provider (i.e. gcs, s3, azure etc)")
	cmd.Flags().StringVar(&storageOpt.bucket, "bucket", storageOpt.bucket, "Name of the cloud bucket/container")
	cmd.Flags().StringVar(&storageOpt.endpoint, "endpoint", storageOpt.endpoint, "Endpoint for s3/s3 compatible backend")
	cmd.Flags().StringVar(&storageOpt.endpoint, "endpoint", storageOpt.endpoint, "Region for s3/s3 compatible backend")
	cmd.Flags().Int64Var(&storageOpt.maxConnections, "max-connections", storageOpt.maxConnections, "Specify maximum concurrent connections for GCS, Azure and B2 backend")
	cmd.Flags().StringVar(&storageOpt.secret, "secret", storageOpt.secret, "Name of the Storage Secret")
	cmd.Flags().StringVar(&storageOpt.prefix, "prefix", storageOpt.prefix, "Prefix denotes the directory inside the backend")
	cmd.Flags().StringVar(&storageOpt.deletionPolicy, "deletion-policy", storageOpt.deletionPolicy, "DeletionPolicy specifies what to do when BackupStorage is deleted")

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
	storageName := fmt.Sprintf("%s-%s-%d", opt.provider, "storage", time.Now().Unix())
	klog.Infof("Creating Repository: %s to the Namespace: %s", storageName, srcNamespace)
	fromAllNameSpace := apis.NamespacesFromAll
	deletionPolicy := storageapi.DeletionPolicyDelete
	if opt.deletionPolicy == "WipeOut" {
		deletionPolicy = storageapi.DeletionPolicyWipeOut
	}
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
			DeletionPolicy: deletionPolicy,
		},
	}
	return storage
}

func (opt *storageOption) getBackendInfo() storageapi.Backend {
	var backend storageapi.Backend
	switch opt.provider {
	case string(storageapi.ProviderGCS):
		backend = storageapi.Backend{
			GCS: &storageapi.GCSSpec{
				Bucket:         opt.bucket,
				Prefix:         opt.prefix,
				MaxConnections: opt.maxConnections,
				Secret:         opt.secret,
			},
		}
	case string(storageapi.ProviderAzure):
		backend = storageapi.Backend{
			Azure: &storageapi.AzureSpec{
				Container:      opt.bucket,
				Prefix:         opt.prefix,
				MaxConnections: opt.maxConnections,
				Secret:         opt.secret,
			},
		}
	case string(storageapi.ProviderS3):
		backend = storageapi.Backend{
			S3: &storageapi.S3Spec{
				Bucket:   opt.bucket,
				Prefix:   opt.prefix,
				Endpoint: opt.endpoint,
				Region:   opt.region,
				Secret:   opt.secret,
			},
		}
	case string(storageapi.ProviderB2):
		backend = storageapi.Backend{
			B2: &storageapi.B2Spec{
				Bucket:         opt.bucket,
				Prefix:         opt.prefix,
				MaxConnections: opt.maxConnections,
				Secret:         opt.secret,
			},
		}
	case string(storageapi.ProviderSwift):
		backend = storageapi.Backend{
			Swift: &storageapi.SwiftSpec{
				Container: opt.bucket,
				Prefix:    opt.prefix,
				Secret:    opt.secret,
			},
		}
	case string(storageapi.ProviderRest):
		backend = storageapi.Backend{
			Rest: &storageapi.RestServerSpec{
				URL:    opt.endpoint,
				Secret: opt.secret,
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

func backupPVC(pvc *corev1.PersistentVolumeClaim) error {
	// TODO: create bc and take instant backup
	return nil
}
