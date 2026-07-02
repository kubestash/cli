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

package cloud

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	storageapi "kubestash.dev/apimachinery/apis/storage/v1alpha1"
	"kubestash.dev/apimachinery/pkg/blob"
	"kubestash.dev/apimachinery/pkg/retry"

	"github.com/aws/aws-sdk-go-v2/aws"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	defaultExpirationBuffer = time.Hour
	envAWSAccessKeyID       = "AWS_ACCESS_KEY_ID"
	envAWSSecretAccessKey   = "AWS_SECRET_ACCESS_KEY"
	envAWSSessionToken      = "AWS_SESSION_TOKEN"
)

type S3CredentialManager struct {
	mu      sync.RWMutex
	creds   *aws.Credentials
	client  client.Client
	storage *storageapi.BackupStorage
	buffer  time.Duration
}

func NewS3CredentialManager(client client.Client, storage *storageapi.BackupStorage) *S3CredentialManager {
	return &S3CredentialManager{
		client:  client,
		storage: storage,
		buffer:  defaultExpirationBuffer,
	}
}

func (m *S3CredentialManager) SetExpirationBuffer(d time.Duration) *S3CredentialManager {
	m.buffer = d
	return m
}

// GetCredentialsWithRefresh returns current credentials, refreshing if necessary
func (m *S3CredentialManager) GetCredentialsWithRefresh(ctx context.Context) (*aws.Credentials, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.needsRefresh() {
		return m.creds, nil
	}

	var err error
	m.creds, err = m.GetWithRetry(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh credentials for %s/%s: %w", m.storage.Namespace, m.storage.Name, err)
	}

	klog.InfoS("Successfully refreshed S3 credentials", "namespace", m.storage.Namespace, "name", m.storage.Name)
	return m.creds, nil
}

func (m *S3CredentialManager) GetWithRetry(ctx context.Context) (*aws.Credentials, error) {
	b, err := blob.NewBlob(ctx, m.client, m.storage)
	if err != nil {
		return nil, fmt.Errorf("create blob client: %w", err)
	}

	retryConfig := retry.NewRetryConfig(func(config *retry.RetryConfig) {
		config.ShouldRetry = func(err error, _ string) bool {
			if err == nil {
				return false
			}
			msg := err.Error()
			return strings.Contains(msg, "failed to refresh cached credentials") ||
				strings.Contains(msg, "failed to retrieve credentials") ||
				strings.Contains(msg, "AssumeRoleWithWebIdentity")
		}
	})

	result, err := retryConfig.RunWithRetry(ctx, func() (any, error) {
		return b.GetS3Credentials(ctx, false)
	})
	if err != nil {
		return nil, fmt.Errorf("get S3 credentials: %w", err)
	}

	creds, ok := result.(*aws.Credentials)
	if !ok {
		return nil, fmt.Errorf("unexpected credential type: %T", result)
	}
	klog.Infof("Successfully fetched S3 credentials for %s/%s", m.storage.Namespace, m.storage.Name)
	return creds, nil
}

func (m *S3CredentialManager) ExportToEnv() error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.creds == nil {
		return errors.New("no credentials available to export")
	}

	envs := ConvertCredsToEnvMap(m.creds)
	for key, value := range envs {
		if err := os.Setenv(key, value); err != nil {
			return fmt.Errorf("failed to set %s: %w", key, err)
		}
	}

	return nil
}

func (m *S3CredentialManager) needsRefresh() bool {
	if m.creds == nil {
		return true
	}
	return m.isExpiring(m.creds)
}

func (m *S3CredentialManager) isExpiring(creds *aws.Credentials) bool {
	if !creds.CanExpire {
		return false
	}
	return time.Until(creds.Expires) < m.buffer
}

func ConvertCredsToEnvMap(creds *aws.Credentials) map[string]string {
	env := map[string]string{
		envAWSAccessKeyID:     creds.AccessKeyID,
		envAWSSecretAccessKey: creds.SecretAccessKey,
	}
	if creds.SessionToken != "" {
		env[envAWSSessionToken] = creds.SessionToken
	}
	return env
}
