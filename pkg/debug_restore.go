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
	"os"

	"github.com/spf13/cobra"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	meta_util "kmodules.xyz/client-go/meta"
	"kubestash.dev/apimachinery/apis"
	coreapi "kubestash.dev/apimachinery/apis/core/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func NewCmdDebugRestore() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "restore",
		Short:             `Debug restore`,
		Long:              `Debug common KubeStash restore issues`,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 || args[0] == "" {
				return fmt.Errorf("restoresession name not found")
			}

			rs := &coreapi.RestoreSession{
				ObjectMeta: metav1.ObjectMeta{
					Name:      args[0],
					Namespace: srcNamespace,
				},
			}
			if err := klient.Get(context.Background(), client.ObjectKeyFromObject(rs), rs); err != nil {
				return err
			}

			if rs.Status.Phase == coreapi.RestoreInvalid {
				return showTableForInvalidRestore(rs)
			}

			if rs.Status.Phase == coreapi.RestoreFailed {
				return showTableForFailedRestore(rs)
			}

			return nil
		},
	}

	return cmd
}

func showTableForInvalidRestore(rs *coreapi.RestoreSession) error {
	var data [][]string
	for _, cond := range rs.Status.Conditions {
		if cond.Type == coreapi.TypeValidationPassed {
			data = append(data, []string{Condition, cond.Message})
		}
	}

	_, err := fmt.Fprintf(os.Stdout, "Debugging RestoreSession: %s/%s\n", rs.Namespace, rs.Name)
	if err != nil {
		return err
	}

	return createTable(data)
}

func showTableForFailedRestore(rs *coreapi.RestoreSession) error {
	var data [][]string

	for _, cond := range rs.Status.Conditions {
		if cond.Status == metav1.ConditionFalse {
			data = append(data, []string{Condition, cond.Message})
		}
	}

	componentFailed := false
	for _, rp := range rs.Status.Components {
		if rp.Phase == coreapi.RestoreFailed {
			componentFailed = true
			data = append(data, []string{Component, rp.Error})
		}
	}

	_, err := fmt.Fprintf(os.Stdout, "Debugging RestoreSession: %s/%s\n", rs.Namespace, rs.Name)
	if err != nil {
		return err
	}

	if err := createTable(data); err != nil {
		return err
	}

	if componentFailed {
		pods := core.PodList{}
		if err := klient.List(context.Background(), &pods, client.MatchingLabels(getLabels(rs))); err != nil {
			return err
		}
		for _, pod := range pods.Items {
			if err := showLogs(pod, "--all-containers"); err != nil {
				return err
			}
			_, err := fmt.Fprintf(os.Stdout, "\n\n")
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func getLabels(rs *coreapi.RestoreSession) map[string]string {
	labels := rs.OffshootLabels()
	labels[meta_util.ComponentLabelKey] = apis.KubeStashRestoreComponent
	return labels
}
