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
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
	coreapi "kubestash.dev/apimachinery/apis/core/v1alpha1"
	storageapi "kubestash.dev/apimachinery/apis/storage/v1alpha1"
)

func NewRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:               "kubectl-kubestash",
		Short:             `kubectl plugin for KubeStash`,
		Long:              `kubectl plugin for KubeStash. For more information, visit here: https://appscode.com/products/kubestash`,
		DisableAutoGenTag: true,
		PersistentPreRun: func(c *cobra.Command, args []string) {
			scheme := runtime.NewScheme()
			utilruntime.Must(coreapi.AddToScheme(scheme))
			utilruntime.Must(storageapi.AddToScheme(scheme))
			utilruntime.Must(corev1.AddToScheme(scheme))
		},
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

	return rootCmd
}
