/*
Copyright AppsCode Inc. and Contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package resolver

import (
	"context"
	"fmt"

	storageapi "kubestash.dev/apimachinery/apis/storage/v1alpha1"
	"kubestash.dev/apimachinery/pkg/cloud"

	"gomodules.xyz/restic"
	core "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// NewBackupStorageResolver creates a StorageConfigResolver that resolves storage configuration
// from a BackupStorage custom resource. This is the default resolver for the kubestash project.
func NewBackupStorageResolver(kbClient client.Client, bs *storageapi.BackupStorage) restic.StorageConfigResolver {
	return func(backend *restic.Backend) error {
		return ResolveResticBackend(kbClient, bs, backend)
	}
}

func ResolveResticBackend(kbClient client.Client, bs *storageapi.BackupStorage, backend *restic.Backend) error {
	secretName, err := resolveStorageConfig(bs, backend)
	if err != nil {
		return fmt.Errorf("failed to resolve storage config for BackupStorage %s/%s: %w", bs.Namespace, bs.Name, err)
	}

	if secretName != "" {
		return setSecretIntoBackend(kbClient, bs, backend, secretName)
	} else if backend.Provider == string(storageapi.ProviderS3) {
		return setS3SecretsManuallyIntoBackend(kbClient, bs, backend)
	}

	return nil
}

func resolveStorageConfig(bs *storageapi.BackupStorage, backend *restic.Backend) (string, error) {
	var secretName string
	switch {
	case bs.Spec.Storage.S3 != nil:
		s3 := bs.Spec.Storage.S3
		secretName = s3.SecretName

		backend.StorageConfig = &restic.StorageConfig{
			Provider:       string(storageapi.ProviderS3),
			Bucket:         s3.Bucket,
			Endpoint:       s3.Endpoint,
			Region:         s3.Region,
			Prefix:         s3.Prefix,
			InsecureTLS:    s3.InsecureTLS,
			MaxConnections: s3.MaxConnections,
		}

	case bs.Spec.Storage.GCS != nil:
		gcs := bs.Spec.Storage.GCS
		secretName = gcs.SecretName

		backend.StorageConfig = &restic.StorageConfig{
			Provider:       string(storageapi.ProviderGCS),
			Bucket:         gcs.Bucket,
			Prefix:         gcs.Prefix,
			MaxConnections: gcs.MaxConnections,
		}

	case bs.Spec.Storage.Azure != nil:
		azure := bs.Spec.Storage.Azure
		secretName = azure.SecretName

		backend.StorageConfig = &restic.StorageConfig{
			Provider:            string(storageapi.ProviderAzure),
			Bucket:              azure.Container,
			Prefix:              azure.Prefix,
			AzureStorageAccount: azure.StorageAccount,
			MaxConnections:      azure.MaxConnections,
		}

	case bs.Spec.Storage.Local != nil:
		local := bs.Spec.Storage.Local

		backend.StorageConfig = &restic.StorageConfig{
			Provider:       string(storageapi.ProviderLocal),
			Bucket:         local.MountPath,
			Prefix:         local.SubPath,
			MaxConnections: local.MaxConnections,
		}

		if backend.MountPath != "" {
			backend.Bucket = backend.MountPath
		}

	default:
		return "", fmt.Errorf("no storage backend configured in BackupStorage %s/%s", bs.Namespace, bs.Name)
	}
	return secretName, nil
}

func setSecretIntoBackend(kbClient client.Client, bs *storageapi.BackupStorage, backend *restic.Backend, secretName string) error {
	secret := &core.Secret{}
	if err := kbClient.Get(context.Background(),
		client.ObjectKey{Name: secretName, Namespace: bs.Namespace},
		secret); err != nil {
		return fmt.Errorf("failed to get storage Secret %s/%s: %w", bs.Namespace, secretName, err)
	}
	backend.StorageSecret = secret
	return nil
}

func setS3SecretsManuallyIntoBackend(kbClient client.Client, bs *storageapi.BackupStorage, backend *restic.Backend) error {
	credManager := cloud.NewS3CredentialManager(kbClient, bs)
	creds, err := credManager.GetWithRetry(context.Background())
	if err != nil {
		return fmt.Errorf("failed to get S3 credentials for BackupStorage %s/%s: %w", bs.Namespace, bs.Name, err)
	}
	backend.Envs = cloud.ConvertCredsToEnvMap(creds)
	return nil
}
