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
	"errors"
	"fmt"
	"net/url"
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

	if w.config.BackupStorage == nil {
		return errors.New("missing BackupStorage reference")
	}

	if err := w.setBackupStorageVariables(); err != nil {
		return fmt.Errorf("failed to set BackupStorage variables: %w", err)
	}

	if w.config.storageSecret == nil {
		return errors.New("missing storage Secret")
	}

	if err := w.exportSecretKey(RESTIC_PASSWORD, true); err != nil {
		return err
	}

	tmpDir, err := os.MkdirTemp(w.config.ScratchDir, "tmp-")
	if err != nil {
		return err
	}
	w.sh.SetEnv(TMPDIR, tmpDir)

	if _, ok := w.config.storageSecret.Data[CA_CERT_DATA]; ok {
		filePath, err := w.writeSecretKeyToFile(CA_CERT_DATA, "ca.crt")
		if err != nil {
			return err
		}
		w.config.CacertFile = filePath
	}

	if w.config.EnableCache {
		cacheDir := filepath.Join(w.config.ScratchDir, resticCacheDir)
		if err := os.MkdirAll(cacheDir, 0o755); err != nil {
			return err
		}
	}

	// path = strings.TrimPrefix(path, "/")

	switch w.config.provider {

	case storage.ProviderLocal:
		r := fmt.Sprintf("%s/%s", w.config.bucket, w.config.Directory)
		w.sh.SetEnv(RESTIC_REPOSITORY, r)

	case storage.ProviderS3:
		r := fmt.Sprintf("s3:%s/%s", w.config.endpoint, filepath.Join(w.config.bucket, w.config.path, w.config.Directory))
		w.sh.SetEnv(RESTIC_REPOSITORY, r)

		if err := w.exportSecretKey(AWS_ACCESS_KEY_ID, false); err != nil {
			return err
		}

		if err := w.exportSecretKey(AWS_SECRET_ACCESS_KEY, false); err != nil {
			return err
		}

		if w.config.region != "" {
			w.sh.SetEnv(AWS_DEFAULT_REGION, w.config.region)
		}

	case storage.ProviderGCS:
		r := fmt.Sprintf("gs:%s:/%s", w.config.bucket, filepath.Join(w.config.path, w.config.Directory))
		w.sh.SetEnv(RESTIC_REPOSITORY, r)

		if err := w.exportSecretKey(GOOGLE_PROJECT_ID, false); err != nil {
			return err
		}

		if w.isSecretKeyExist(GOOGLE_SERVICE_ACCOUNT_JSON_KEY) {
			filePath, err := w.writeSecretKeyToFile(GOOGLE_SERVICE_ACCOUNT_JSON_KEY, GOOGLE_SERVICE_ACCOUNT_JSON_KEY)
			if err != nil {
				return err
			}
			w.sh.SetEnv(GOOGLE_APPLICATION_CREDENTIALS, filePath)
		}
	case storage.ProviderAzure:
		r := fmt.Sprintf("azure:%s:/%s", w.config.bucket, filepath.Join(w.config.path, w.config.Directory))
		w.sh.SetEnv(RESTIC_REPOSITORY, r)

		if w.config.storageAccount == "" {
			return fmt.Errorf("storageAccount name is empty")
		}
		w.sh.SetEnv(AZURE_ACCOUNT_NAME, w.config.storageAccount)

		if err := w.exportSecretKey(AZURE_ACCOUNT_KEY, false); err != nil {
			return err
		}

	case storage.ProviderSwift:
		r := fmt.Sprintf("swift:%s:/%s", w.config.bucket, filepath.Join(w.config.path, w.config.Directory))
		w.sh.SetEnv(RESTIC_REPOSITORY, r)

		// For keystone v1 authentication
		// Necessary Envs:
		// ST_AUTH
		// ST_USER
		// ST_KEY
		if err := w.exportSecretKey(ST_AUTH, false); err != nil {
			return err
		}

		if err := w.exportSecretKey(ST_USER, false); err != nil {
			return err
		}

		if err := w.exportSecretKey(ST_KEY, false); err != nil {
			return err
		}

		// For keystone v2 authentication (some variables are optional)
		// Necessary Envs:
		// OS_AUTH_URL
		// OS_REGION_NAME
		// OS_USERNAME
		// OS_PASSWORD
		// OS_TENANT_ID
		// OS_TENANT_NAME
		if err := w.exportSecretKey(OS_AUTH_URL, false); err != nil {
			return err
		}

		if err := w.exportSecretKey(OS_REGION_NAME, false); err != nil {
			return err
		}

		if err := w.exportSecretKey(OS_USERNAME, false); err != nil {
			return err
		}

		if err := w.exportSecretKey(OS_PASSWORD, false); err != nil {
			return err
		}

		if err := w.exportSecretKey(OS_TENANT_ID, false); err != nil {
			return err
		}

		if err := w.exportSecretKey(OS_TENANT_NAME, false); err != nil {
			return err
		}

		// For keystone v3 authentication (some variables are optional)
		// Necessary Envs:
		// OS_AUTH_URL (already set in v2 authentication section)
		// OS_REGION_NAME (already set in v2 authentication section)
		// OS_USERNAME (already set in v2 authentication section)
		// OS_PASSWORD (already set in v2 authentication section)
		// OS_USER_DOMAIN_NAME
		// OS_PROJECT_NAME
		// OS_PROJECT_DOMAIN_NAME
		if err := w.exportSecretKey(OS_USER_DOMAIN_NAME, false); err != nil {
			return err
		}

		if err := w.exportSecretKey(OS_PROJECT_NAME, false); err != nil {
			return err
		}

		if err := w.exportSecretKey(OS_PROJECT_DOMAIN_NAME, false); err != nil {
			return err
		}

		// For keystone v3 application credential authentication (application credential id)
		// Necessary Envs:
		// OS_AUTH_URL (already set in v2 authentication section)
		// OS_APPLICATION_CREDENTIAL_ID
		// OS_APPLICATION_CREDENTIAL_SECRET
		if err := w.exportSecretKey(OS_APPLICATION_CREDENTIAL_ID, false); err != nil {
			return err
		}

		if err := w.exportSecretKey(OS_APPLICATION_CREDENTIAL_SECRET, false); err != nil {
			return err
		}

		// For keystone v3 application credential authentication (application credential name)
		// Necessary Envs:
		// OS_AUTH_URL (already set in v2 authentication section)
		// OS_USERNAME (already set in v2 authentication section)
		// OS_USER_DOMAIN_NAME (already set in v3 authentication section)
		// OS_APPLICATION_CREDENTIAL_NAME
		// OS_APPLICATION_CREDENTIAL_SECRET (already set in v3 authentication with credential id section)
		if err := w.exportSecretKey(OS_APPLICATION_CREDENTIAL_NAME, false); err != nil {
			return err
		}

		// For authentication based on tokens
		// Necessary Envs:
		// OS_STORAGE_URL
		// OS_AUTH_TOKEN
		if err := w.exportSecretKey(OS_STORAGE_URL, false); err != nil {
			return err
		}

		if err := w.exportSecretKey(OS_AUTH_TOKEN, false); err != nil {
			return err
		}

	case storage.ProviderB2:
		r := fmt.Sprintf("b2:%s:/%s", w.config.bucket, filepath.Join(w.config.path, w.config.Directory))
		w.sh.SetEnv(RESTIC_REPOSITORY, r)

		if err := w.exportSecretKey(B2_ACCOUNT_ID, true); err != nil {
			return err
		}

		if err := w.exportSecretKey(B2_ACCOUNT_KEY, true); err != nil {
			return err
		}

	case storage.ProviderRest:
		u, err := url.Parse(w.config.endpoint)
		if err != nil {
			return err
		}

		if username, hasUserKey := w.config.storageSecret.Data[REST_SERVER_USERNAME]; hasUserKey {
			if password, hasPassKey := w.config.storageSecret.Data[REST_SERVER_PASSWORD]; hasPassKey {
				u.User = url.UserPassword(string(username), string(password))
			} else {
				u.User = url.User(string(username))
			}
		}
		// u.Path = filepath.Join(u.Path, w.config.Path) // path integrated with url
		r := fmt.Sprintf("rest:%s", u.String())
		w.sh.SetEnv(RESTIC_REPOSITORY, r)
	}

	return nil
}

func (w *ResticWrapper) exportSecretKey(key string, required bool) error {
	if v, ok := w.config.storageSecret.Data[key]; !ok {
		if required {
			return fmt.Errorf("storage Secret missing %s key", key)
		}
	} else {
		w.sh.SetEnv(key, string(v))
	}
	return nil
}

func (w *ResticWrapper) isSecretKeyExist(key string) bool {
	_, ok := w.config.storageSecret.Data[key]
	return ok
}

func (w *ResticWrapper) writeSecretKeyToFile(key, name string) (string, error) {
	v, ok := w.config.storageSecret.Data[key]
	if !ok {
		return "", fmt.Errorf("storage Secret missing %s key", key)
	}

	tmpDir := w.GetEnv(TMPDIR)
	filePath := filepath.Join(tmpDir, name)

	if err := os.WriteFile(filePath, v, 0o755); err != nil {
		return "", err
	}
	return filePath, nil
}

func (w *ResticWrapper) setBackupStorageVariables() error {
	bs := &v1alpha1.BackupStorage{
		ObjectMeta: metav1.ObjectMeta{
			Name:      w.config.BackupStorage.Name,
			Namespace: w.config.BackupStorage.Namespace,
		},
	}

	if err := w.config.Client.Get(context.Background(), client.ObjectKeyFromObject(bs), bs); err != nil {
		return err
	}

	var secret string

	if s3 := bs.Spec.Storage.S3; s3 != nil {
		w.config.provider = v1alpha1.ProviderS3
		w.config.region = s3.Region
		w.config.bucket = s3.Bucket
		w.config.endpoint = s3.Endpoint
		w.config.path = s3.Prefix
		secret = s3.Secret
	}

	if gcs := bs.Spec.Storage.GCS; gcs != nil {
		w.config.provider = v1alpha1.ProviderGCS
		w.config.bucket = gcs.Bucket
		w.config.path = gcs.Prefix
		w.config.MaxConnections = gcs.MaxConnections
		secret = gcs.Secret
	}

	if azure := bs.Spec.Storage.Azure; azure != nil {
		w.config.provider = v1alpha1.ProviderAzure
		w.config.storageAccount = azure.StorageAccount
		w.config.bucket = azure.Container
		w.config.path = azure.Prefix
		w.config.MaxConnections = azure.MaxConnections
		secret = azure.Secret
	}

	if local := bs.Spec.Storage.Local; local != nil {
		w.config.provider = v1alpha1.ProviderLocal
		w.config.bucket = local.MountPath
		w.config.path = local.SubPath

		var err error
		w.config.storageSecret, err = w.getSecret(w.config.EncryptionSecret)
		if err != nil {
			return err
		}

		if w.config.MountPath != "" {
			w.config.bucket = w.config.MountPath
		}

		return nil
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

	es, err := w.getSecret(w.config.EncryptionSecret)
	if err != nil {
		return fmt.Errorf("failed to get Encryption Secret %s/%s: %w", w.config.EncryptionSecret.Namespace, w.config.EncryptionSecret.Name, err)
	}

	w.config.storageSecret = mergeSecretData(ss, es)
	return nil
}

func (w *ResticWrapper) getSecret(ref *kmapi.ObjectReference) (*core.Secret, error) {
	secret := &core.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ref.Name,
			Namespace: ref.Namespace,
		},
	}

	if err := w.config.Client.Get(context.Background(), client.ObjectKeyFromObject(secret), secret); err != nil {
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
