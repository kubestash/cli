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
	"strings"

	"github.com/spf13/cobra"
	"gomodules.xyz/go-sh"
	"k8s.io/klog/v2"
)

func NewCmdDebugOperator() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "operator",
		Short:             `Debug KubeStash operator`,
		Long:              `Show debugging information for KubeStash operator`,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := showVersionInformation(); err != nil {
				return err
			}
			return debugOperator()
		},
	}
	return cmd
}

func showVersionInformation() error {
	if err := showKubernetesVersion(); err != nil {
		return err
	}

	return showKubeStashVersion()
}

func showKubernetesVersion() error {
	klog.Infoln("\n\n\n==================[ Kubernetes Version ]==================")
	return sh.Command(CmdKubectl, "version", "--short").Run()
}

func showKubeStashVersion() error {
	pod, err := getOperatorPod()
	if err != nil {
		return err
	}
	var kubestashBinary string
	if strings.Contains(pod.Name, "kubestash-enterprise") {
		kubestashBinary = "/kubestash-enterprise"
	} else {
		kubestashBinary = "/kubestash"
	}
	klog.Infoln("\n\n\n==================[ KubeStash Version ]==================")
	return sh.Command(CmdKubectl, "exec", "-it", "-n", pod.Namespace, pod.Name, "-c", "operator", "--", kubestashBinary, "version").Run()
}

func debugOperator() error {
	pod, err := getOperatorPod()
	if err != nil {
		return err
	}
	return showLogs(pod, "-c", "operator")
}
