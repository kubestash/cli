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

	"github.com/spf13/cobra"
	v "gomodules.xyz/x/version"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kmapi "kmodules.xyz/client-go/api/v1"
	configapi "kubestash.dev/apimachinery/apis/config/v1alpha1"
	"kubestash.dev/apimachinery/pkg/blob"
	"sigs.k8s.io/yaml"
)

const (
	debugMetaFile   = "debug_metadata.yaml"
	contentTypeYAML = "application/yaml"
)

func NewCmdDebugBackupStorage() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "backupstorage",
		Short:             `Debug BackupStorage connection`,
		Long:              `Debug BackupStorage connection by uploading and deleting sample data`,
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			ctx := context.Background()
			backupStorage, err := getBackupStorage(kmapi.ObjectReference{
				Name:      args[0],
				Namespace: srcNamespace,
			})
			if err != nil {
				return err
			}

			backend, err := blob.NewBlob(ctx, klient, backupStorage)
			if err != nil {
				return err
			}

			d, err := yaml.Marshal(sampleBackendMeta())
			if err != nil {
				return err
			}

			return backend.Debug(ctx, debugMetaFile, d, contentTypeYAML)
		},
	}
	return cmd
}

func sampleBackendMeta() configapi.BackendMeta {
	return configapi.BackendMeta{
		TypeMeta: metav1.TypeMeta{
			Kind:       configapi.ResourceKindBackendMeta,
			APIVersion: configapi.GroupVersion.String(),
		},
		CreationTimestamp: metav1.Now(),
		OperatorVersion:   v.Version.Version,
	}
}
