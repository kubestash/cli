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

package restic

import (
	"context"
	"fmt"
	"k8s.io/apimachinery/pkg/util/errors"
	"os"
	"path/filepath"

	"kubestash.dev/apimachinery/apis/storage/v1alpha1"

	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kmapi "kmodules.xyz/client-go/api/v1"
	meta_util "kmodules.xyz/client-go/meta"
	storage "kmodules.xyz/objectstore-api/api/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	RESTIC_REPOSITORY   = "RESTIC_REPOSITORY"
	RESTIC_PASSWORD     = "RESTIC_PASSWORD"
	RESTIC_PROGRESS_FPS = "RESTIC_PROGRESS_FPS"
	TMPDIR              = "TMPDIR"

	AWS_ACCESS_KEY_ID     = "AWS_ACCESS_KEY_ID"
	AWS_SECRET_ACCESS_KEY = "AWS_SECRET_ACCESS_KEY"
	AWS_DEFAULT_REGION    = "AWS_DEFAULT_REGION"

	GOOGLE_PROJECT_ID               = "GOOGLE_PROJECT_ID"
	GOOGLE_SERVICE_ACCOUNT_JSON_KEY = "GOOGLE_SERVICE_ACCOUNT_JSON_KEY"
	GOOGLE_APPLICATION_CREDENTIALS  = "GOOGLE_APPLICATION_CREDENTIALS"

	AZURE_ACCOUNT_NAME = "AZURE_ACCOUNT_NAME"
	AZURE_ACCOUNT_KEY  = "AZURE_ACCOUNT_KEY"

	REST_SERVER_USERNAME = "REST_SERVER_USERNAME"
	REST_SERVER_PASSWORD = "REST_SERVER_PASSWORD"

	B2_ACCOUNT_ID  = "B2_ACCOUNT_ID"
	B2_ACCOUNT_KEY = "B2_ACCOUNT_KEY"

	// For keystone v1 authentication
	ST_AUTH = "ST_AUTH"
	ST_USER = "ST_USER"
	ST_KEY  = "ST_KEY"
	// For keystone v2 authentication (some variables are optional)
	OS_AUTH_URL    = "OS_AUTH_URL"
	OS_REGION_NAME = "OS_REGION_NAME"
	OS_USERNAME    = "OS_USERNAME"
	OS_PASSWORD    = "OS_PASSWORD"
	OS_TENANT_ID   = "OS_TENANT_ID"
	OS_TENANT_NAME = "OS_TENANT_NAME"
	// For keystone v3 authentication (some variables are optional)
	OS_USER_DOMAIN_NAME    = "OS_USER_DOMAIN_NAME"
	OS_PROJECT_NAME        = "OS_PROJECT_NAME"
	OS_PROJECT_DOMAIN_NAME = "OS_PROJECT_DOMAIN_NAME"
	// For keystone v3 application credential authentication (application credential id)
	OS_APPLICATION_CREDENTIAL_ID     = "OS_APPLICATION_CREDENTIAL_ID"
	OS_APPLICATION_CREDENTIAL_SECRET = "OS_APPLICATION_CREDENTIAL_SECRET"
	// For keystone v3 application credential authentication (application credential name)
	OS_APPLICATION_CREDENTIAL_NAME = "OS_APPLICATION_CREDENTIAL_NAME"
	// For authentication based on tokens
	OS_STORAGE_URL = "OS_STORAGE_URL"
	OS_AUTH_TOKEN  = "OS_AUTH_TOKEN"

	// For using certs in Minio server or REST server
	CA_CERT_DATA = "CA_CERT_DATA"

	// ref: https://github.com/restic/restic/blob/master/doc/manual_rest.rst#temporary-files
	resticCacheDir = "restic-cache"
)

func (w *ResticWrapper) setupEnv() error {
	// Set progress report frequency.
	// 0.016666 is for one report per minute.
	// ref: https://restic.readthedocs.io/en/stable/manual_rest.html
	w.sh.SetEnv(RESTIC_PROGRESS_FPS, "0.016666")
	if w.Config.EnableCache {
		cacheDir := filepath.Join(w.Config.ScratchDir, resticCacheDir)
		if err := os.MkdirAll(cacheDir, 0o755); err != nil {
			return err
		}
	}

	for _, b := range w.Config.Backends {
		err := w.setupEnvsForBackend(b)
		if err != nil {
			b.Error = errors.NewAggregate([]error{b.Error, err})
		}
	}
	return nil
}

func (w *ResticWrapper) setupEnvsForBackend(b *Backend) error {
	if b.BackupStorage == nil {
		return fmt.Errorf("missing BackupStorage reference")
	}

	if err := w.setBackupStorageVariables(b); err != nil {
		return fmt.Errorf("failed to set BackupStorage variables. Reason: %w", err)
	}
	if b.storageSecret == nil {
		return fmt.Errorf("missing storage Secret")
	}

	b.envs = map[string]string{}

	if value, err := w.getSecretKey(b.storageSecret, RESTIC_PASSWORD, true); err != nil {
		return err
	} else {
		b.envs[RESTIC_PASSWORD] = value
	}

	tmpDir, err := os.MkdirTemp(w.Config.ScratchDir, fmt.Sprintf("%s-tmp-", b.Repository))
	if err != nil {
		return err
	}
	b.envs[TMPDIR] = tmpDir

	if _, ok := b.storageSecret.Data[CA_CERT_DATA]; ok {
		if filePath, err := w.writeSecretKeyToFile(tmpDir, b.storageSecret, CA_CERT_DATA, "ca.crt"); err != nil {
			return err
		} else {
			b.CaCertFile = filePath
		}
	}
	switch b.provider {

	case storage.ProviderLocal:
		b.envs[RESTIC_REPOSITORY] = fmt.Sprintf("%s/%s", b.bucket, b.Directory)

	case storage.ProviderS3:
		b.envs[RESTIC_REPOSITORY] = fmt.Sprintf("s3:%s/%s", b.endpoint, filepath.Join(b.bucket, b.path, b.Directory))
		if val, err := w.getSecretKey(b.storageSecret, AWS_ACCESS_KEY_ID, false); err != nil {
			return err
		} else {
			b.envs[AWS_ACCESS_KEY_ID] = val
		}

		if val, err := w.getSecretKey(b.storageSecret, AWS_SECRET_ACCESS_KEY, false); err != nil {
			return err
		} else {
			b.envs[AWS_SECRET_ACCESS_KEY] = val
		}

		if b.region != "" {
			b.envs[AWS_DEFAULT_REGION] = b.region
		}

	case storage.ProviderGCS:
		b.envs[RESTIC_REPOSITORY] = fmt.Sprintf("gs:%s:/%s", b.bucket, filepath.Join(b.path, b.Directory))
		if val, err := w.getSecretKey(b.storageSecret, GOOGLE_SERVICE_ACCOUNT_JSON_KEY, false); err != nil {
			return err
		} else {
			b.envs[GOOGLE_SERVICE_ACCOUNT_JSON_KEY] = val
		}

		if w.isSecretKeyExist(b.storageSecret, GOOGLE_SERVICE_ACCOUNT_JSON_KEY) {
			if filePath, err := w.writeSecretKeyToFile(tmpDir, b.storageSecret, GOOGLE_SERVICE_ACCOUNT_JSON_KEY, GOOGLE_SERVICE_ACCOUNT_JSON_KEY); err != nil {
				return err
			} else {
				w.sh.SetEnv(GOOGLE_APPLICATION_CREDENTIALS, filePath)
			}
		}
	}

	return nil
}

func (w *ResticWrapper) exportSecretKey(secret *core.Secret, key string, required bool) error {
	if v, ok := secret.Data[key]; !ok {
		if required {
			return fmt.Errorf("storage Secret missing %s key", key)
		}
	} else {
		w.sh.SetEnv(key, string(v))
	}
	return nil
}

func (w *ResticWrapper) getSecretKey(secret *core.Secret, key string, required bool) (string, error) {
	v, ok := secret.Data[key]
	if !ok {
		if required {
			return "", fmt.Errorf("%s storage Secret missing %s key", secret.Name, key)
		}
	}

	return string(v), nil
}

func (w *ResticWrapper) isSecretKeyExist(secret *core.Secret, key string) bool {
	_, ok := secret.Data[key]
	return ok
}

func (w *ResticWrapper) writeSecretKeyToFile(tmpDir string, secret *core.Secret, key, name string) (string, error) {
	v, ok := secret.Data[key]
	if !ok {
		return "", fmt.Errorf("storage Secret missing %s key", key)
	}

	filePath := filepath.Join(tmpDir, name)

	if err := os.WriteFile(filePath, v, 0o755); err != nil {
		return "", err
	}
	return filePath, nil
}

func (w *ResticWrapper) setBackupStorageVariables(b *Backend) error {
	bs := &v1alpha1.BackupStorage{
		ObjectMeta: metav1.ObjectMeta{
			Name:      b.BackupStorage.Name,
			Namespace: b.BackupStorage.Namespace,
		},
	}

	if err := w.Config.Client.Get(context.Background(), client.ObjectKeyFromObject(bs), bs); err != nil {
		return err
	}

	var secret string

	if s3 := bs.Spec.Storage.S3; s3 != nil {
		b.provider = v1alpha1.ProviderS3
		b.region = s3.Region
		b.bucket = s3.Bucket
		b.endpoint = s3.Endpoint
		b.path = s3.Prefix
		b.insecureTLS = s3.InsecureTLS
		secret = s3.SecretName
	}

	if gcs := bs.Spec.Storage.GCS; gcs != nil {
		b.provider = v1alpha1.ProviderGCS
		b.bucket = gcs.Bucket
		b.path = gcs.Prefix
		b.MaxConnections = gcs.MaxConnections
		secret = gcs.SecretName
	}

	if azure := bs.Spec.Storage.Azure; azure != nil {
		b.provider = v1alpha1.ProviderAzure
		b.storageAccount = azure.StorageAccount
		b.bucket = azure.Container
		b.path = azure.Prefix
		b.MaxConnections = azure.MaxConnections
		secret = azure.SecretName
	}

	if local := bs.Spec.Storage.Local; local != nil {
		b.provider = v1alpha1.ProviderLocal
		b.bucket = local.MountPath
		b.path = local.SubPath

		var err error
		b.storageSecret, err = w.getSecret(b.EncryptionSecret)
		if err != nil {
			return err
		}

		if b.MountPath != "" {
			b.bucket = b.MountPath
		}
	}

	ss := &core.Secret{}
	if secret != "" {
		var err error
		ss, err = w.getSecret(&kmapi.ObjectReference{
			Name:      secret,
			Namespace: bs.Namespace,
		})
		if err != nil {
			return fmt.Errorf("failed to get storage Secret %s/%s: %w", bs.Namespace, secret, err)
		}
	}

	es, err := w.getSecret(b.EncryptionSecret)
	if err != nil {
		return fmt.Errorf("failed to get Encryption Secret %s/%s: %w", b.EncryptionSecret.Namespace, b.EncryptionSecret.Name, err)
	}

	b.storageSecret = mergeSecretData(ss, es)

	return nil
}

func (w *ResticWrapper) getSecret(ref *kmapi.ObjectReference) (*core.Secret, error) {
	secret := &core.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ref.Name,
			Namespace: ref.Namespace,
		},
	}

	if err := w.Config.Client.Get(context.Background(), client.ObjectKeyFromObject(secret), secret); err != nil {
		return nil, err
	}

	return secret, nil
}

func mergeSecretData(out, in *core.Secret) *core.Secret {
	if out == nil || in == nil {
		return nil
	}

	if out.Data == nil {
		out.Data = make(map[string][]byte)
	}

	out.StringData = meta_util.MergeKeys(out.StringData, in.StringData)

	for k, v := range in.Data {
		if _, ok := out.Data[k]; !ok {
			out.Data[k] = v
		}
	}

	return out
}
