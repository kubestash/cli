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
	yamlContentType = "application/yaml"
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

			return backend.Debug(ctx, debugMetaFile, d, yamlContentType)
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
