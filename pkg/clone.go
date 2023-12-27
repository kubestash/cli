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
	"github.com/spf13/cobra"
	"gomodules.xyz/flags"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"kubestash.dev/apimachinery/pkg"
)

func NewCmdClone(clientGetter genericclioptions.RESTClientGetter) *cobra.Command {
	cmd := &cobra.Command{
		Use:               "clone",
		Short:             `Clone Kubernetes resources`,
		DisableAutoGenTag: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			flags.EnsureRequiredFlags(cmd, "to-namespace")

<<<<<<< HEAD
			cfg, err := clientGetter.ToRESTConfig()
			if err != nil {
				return fmt.Errorf("failed to read kubeconfig. Reason: %v", err)
			}
=======
			var err error
>>>>>>> f5312de (Update uncached client + Add session list in trigger backup)

			srcNamespace, _, err = clientGetter.ToRawKubeConfigLoader().Namespace()
			if err != nil {
				return err
			}

			klient, err = pkg.NewUncachedClient()
			if err != nil {
				return err
			}

			return nil
		},
	}

	cmd.AddCommand(NewCmdClonePVC())

	cmd.PersistentFlags().StringVar(&dstNamespace, "to-namespace", dstNamespace, "Destination namespace.")

	return cmd
}
