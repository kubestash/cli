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
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"gomodules.xyz/go-sh"
	core "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"
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
	return nil
	// TODO: need to add version in kubestash binary
	// return showKubeStashVersion()
}

func showKubernetesVersion() error {
	klog.Infoln("\n\n\n==================[ Kubernetes Version ]==================")
	return sh.Command("kubectl", "version", "--short").Run()
}

func showKubeStashVersion() error {
	pod, err := getOperatorPod()
	fmt.Println(pod.Name)
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
	return sh.Command("kubectl", "exec", "-it", "-n", pod.Namespace, pod.Name, "-c", "operator", "--", kubestashBinary, "version").Run()
}

func getOperatorPod() (core.Pod, error) {
	// TODO: get operator namespace
	ns := "kubestash"
	var podList core.PodList
	opts := client.ListOption(client.InNamespace(ns))
	if err := klient.List(context.Background(), &podList, opts); err != nil {
		return core.Pod{}, err
	}

	for i := range podList.Items {
		if hasStashContainer(&podList.Items[i]) {
			return podList.Items[i], nil
		}
	}

	return core.Pod{}, fmt.Errorf("operator pod not found")
}

func hasStashContainer(pod *core.Pod) bool {
	if strings.Contains(pod.Name, "stash") {
		for _, c := range pod.Spec.Containers {
			if c.Name == "operator" {
				return true
			}
		}
	}
	return false
}

func debugOperator() error {
	pod, err := getOperatorPod()
	if err != nil {
		return err
	}
	return showLogs(pod, "-c", "operator")
}
