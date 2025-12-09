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
	"fmt"
	"os"

	"kubestash.dev/apimachinery/apis/storage/v1alpha1"

	core "k8s.io/api/core/v1"
	kmapi "kmodules.xyz/client-go/api/v1"
	storage "kmodules.xyz/objectstore-api/api/v1"
)

type backend struct {
	provider       v1alpha1.StorageProvider
	bucket         string
	endpoint       string
	region         string
	insecureTLS    bool
	path           string
	storageAccount string
	envs           map[string]string
}

type Backend struct {
	backend
	storageSecret *core.Secret

	EncryptionSecret *kmapi.ObjectReference
	Directory        string
	BackupStorage    *kmapi.ObjectReference
	MountPath        string
	MaxConnections   int64
	CaCertFile       string
	Repository       string
	Error            error
}

func (b *Backend) createLocalDir() error {
	if b.provider == v1alpha1.ProviderLocal {
		return os.MkdirAll(b.bucket, 0o755)
	}
	return nil
}

func (b *Backend) appendInsecureTLSFlag(args []any) []any {
	if b.insecureTLS {
		return append(args, "--insecure-tls")
	}
	return args
}

func (b *Backend) appendCaCertFlag(args []any) []any {
	if b.CaCertFile != "" {
		return append(args, "--cacert", b.CaCertFile)
	}
	return args
}

func (b *Backend) appendMaxConnectionsFlag(args []any) []any {
	var maxConOption string
	if b.MaxConnections > 0 {
		switch b.provider {
		case storage.ProviderGCS:
			maxConOption = fmt.Sprintf("gs.connections=%d", b.MaxConnections)
		case storage.ProviderAzure:
			maxConOption = fmt.Sprintf("azure.connections=%d", b.MaxConnections)
		case storage.ProviderB2:
			maxConOption = fmt.Sprintf("b2.connections=%d", b.MaxConnections)
		}
	}
	if maxConOption != "" {
		return append(args, "--option", maxConOption)
	}
	return args
}

func (b *Backend) GetCaPath() string {
	return b.CaCertFile
}
