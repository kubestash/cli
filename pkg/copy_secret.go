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
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
	kmapi "kmodules.xyz/client-go/api/v1"
	kmc "kmodules.xyz/client-go/client"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func NewCmdCopySecret() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "secret",
		Short:             `Copy Secret`,
		Long:              `Copy Secret from one namespace to another namespace`,
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			secretName := args[0]

			secret, err := getSecret(kmapi.ObjectReference{
				Name:      secretName,
				Namespace: srcNamespace,
			})
			if err != nil {
				return err
			}

			klog.Infof("Copying Storage Secret %s to %s namespace", secret.Namespace, dstNamespace)
			return createSecret(secret)
		},
	}

	return cmd
}

func createSecret(secret *core.Secret) error {
	newSecret := &core.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        secret.Name,
			Namespace:   dstNamespace,
			Labels:      secret.Labels,
			Annotations: secret.Annotations,
		},
	}
	_, err := kmc.CreateOrPatch(
		context.Background(),
		klient,
		newSecret,
		func(obj client.Object, createOp bool) client.Object {
			in := obj.(*core.Secret)
			in.Data = secret.Data
			return in
		},
	)
	if err != nil {
		return err
	}

	klog.Infof("Secret %s/%s has been copied to %s namespace successfully.", secret.Namespace, secret.Name, dstNamespace)
	return nil
}
