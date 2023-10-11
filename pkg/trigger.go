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

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/klog/v2"
	kmapi "kmodules.xyz/client-go/api/v1"
	kmc "kmodules.xyz/client-go/client"
	core_util "kmodules.xyz/client-go/core/v1"
	coreapi "kubestash.dev/apimachinery/apis/core/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func NewCmdTriggerBackup(clientGetter genericclioptions.RESTClientGetter) *cobra.Command {
	cmd := &cobra.Command{
		Use:               "trigger",
		Short:             `Trigger a backup`,
		Long:              `Trigger a backup by creating BackupSession`,
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			backupConfigName := args[0]

			cfg, err := clientGetter.ToRESTConfig()
			if err != nil {
				return errors.Wrap(err, "failed to read kubeconfig")
			}

			klient, err = newRuntimeClient(cfg)
			if err != nil {
				return err
			}

			namespace, _, err := clientGetter.ToRawKubeConfigLoader().Namespace()
			if err != nil {
				return err
			}

			backupConfig, err := getBackupConfiguration(kmapi.ObjectReference{
				Name:      backupConfigName,
				Namespace: namespace,
			})
			if err != nil {
				return err
			}

			for _, session := range backupConfig.Spec.Sessions {
				_, err := triggerBackup(backupConfig, session)
				if err != nil {
					return err
				}
			}
			return nil
		},
	}

	return cmd
}

func triggerBackup(backupConfig *coreapi.BackupConfiguration, session coreapi.Session) (*coreapi.BackupSession, error) {
	backupSession := &coreapi.BackupSession{
		ObjectMeta: metav1.ObjectMeta{
			Name: coreapi.GenerateBackupSessionName(
				backupConfig.Name,
				session.Name,
			),
			Namespace: backupConfig.Namespace,
		},
		Spec: coreapi.BackupSessionSpec{
			Invoker: &v1.TypedLocalObjectReference{
				APIGroup: &coreapi.GroupVersion.Group,
				Kind:     coreapi.ResourceKindBackupConfiguration,
				Name:     backupConfig.Name,
			},
			Session:   session.Name,
			RetryLeft: 0,
		},
	}

	ownerRef := metav1.NewControllerRef(
		backupConfig,
		coreapi.GroupVersion.WithKind(coreapi.ResourceKindBackupConfiguration),
	)

	_, err := kmc.CreateOrPatch(
		context.Background(),
		klient,
		backupSession,
		func(obj client.Object, createOp bool) client.Object {
			in := obj.(*coreapi.BackupSession)
			in.Spec = backupSession.Spec
			core_util.EnsureOwnerReference(&in.ObjectMeta, ownerRef)
			return in
		},
	)
	if err != nil {
		return nil, err
	}

	klog.Infof("BackupSession %s/%s has been created successfully", backupSession.Namespace, backupSession.Name)
	return backupSession, nil
}
