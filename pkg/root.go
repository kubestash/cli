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
	"github.com/spf13/cobra"
	v "gomodules.xyz/x/version"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
)

func NewRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:               "kubectl-kubestash",
		Short:             `kubectl plugin for KubeStash`,
		Long:              `kubectl plugin for KubeStash. For more information, visit here: https://appscode.com/products/kubestash`,
		DisableAutoGenTag: true,
	}

	flags := rootCmd.PersistentFlags()

	kubeConfigFlags := genericclioptions.NewConfigFlags(true)
	kubeConfigFlags.AddFlags(flags)
	matchVersionKubeConfigFlags := cmdutil.NewMatchVersionFlags(kubeConfigFlags)
	matchVersionKubeConfigFlags.AddFlags(flags)

	f := cmdutil.NewFactory(matchVersionKubeConfigFlags)

	rootCmd.AddCommand(v.NewCmdVersion())
	rootCmd.AddCommand(NewCmdCompletion())

	rootCmd.AddCommand(NewCmdCopy(f))
	rootCmd.AddCommand(NewCmdTriggerBackup(f))
	rootCmd.AddCommand(NewCmdPause(f))
	rootCmd.AddCommand(NewCmdResume(f))
	rootCmd.AddCommand(NewCmdDownload(f))

	return rootCmd
}
