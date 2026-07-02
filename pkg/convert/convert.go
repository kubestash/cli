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

package convert

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"stash.appscode.dev/apimachinery/apis/stash/v1alpha1"
	"stash.appscode.dev/apimachinery/apis/stash/v1beta1"

	"github.com/spf13/cobra"
	"gomodules.xyz/flags"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/klog/v2"
	cu "kmodules.xyz/client-go/client"
	"kmodules.xyz/client-go/tools/parser"
	coreapi "kubestash.dev/apimachinery/apis/core/v1alpha1"
	storageapi "kubestash.dev/apimachinery/apis/storage/v1alpha1"
	"sigs.k8s.io/yaml"
)

var sourceDir, targetDir string

func NewCmdConvert(clientGetter genericclioptions.RESTClientGetter) *cobra.Command {
	cmd := &cobra.Command{
		Use:               "convert",
		Short:             `Convert Stash resources yaml to Kubestash resources yaml`,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags.EnsureRequiredFlags(cmd, "source-dir", "target-dir")

			cfg, err := clientGetter.ToRESTConfig()
			if err != nil {
				return err
			}
			_, err = cu.NewUncachedClient(
				cfg,
				v1alpha1.AddToScheme,
				v1beta1.AddToScheme,
				storageapi.AddToScheme,
				coreapi.AddToScheme,
			)
			if err != nil {
				return err
			}

			if err := parser.ProcessPath(sourceDir, convertResources); err != nil {
				return err
			}
			klog.Infof("Resources convertion completed successfully")
			return nil
		},
	}
	cmd.Flags().StringVar(&sourceDir, "source-dir", sourceDir, "Source directory.")
	cmd.Flags().StringVar(&targetDir, "target-dir", targetDir, "Target directory.")
	return cmd
}

func convertResources(ri parser.ResourceInfo) error {
	klog.Infof("Converting file: %s", ri.Filename)
	switch ri.Object.GetKind() {
	case v1alpha1.ResourceKindRepository:
		return convertRepository(ri)
	case v1beta1.ResourceKindBackupConfiguration:
		return convertBackupConfiguration(ri)
	case v1beta1.ResourceKindBackupBlueprint:
		return convertBackupBlueprint(ri)
	case v1beta1.ResourceKindRestoreSession:
		return convertRestoreSession(ri)
	default:
		return nil
	}
}

func setValidValue(fieldName string) string {
	return fmt.Sprintf("### Set Valid %s ###", fieldName)
}

func writeToTargetDir(srcPath string, addSeparator bool, obj any) error {
	targetPath := strings.ReplaceAll(srcPath, sourceDir, targetDir)
	if err := os.MkdirAll(filepath.Dir(targetPath), os.ModePerm); err != nil {
		return err
	}
	klog.Infof("Writing %s to %s", srcPath, targetPath)

	if addSeparator {
		if err := addSeparatorToTargetFile(targetPath); err != nil {
			return err
		}
	}

	marshalled, err := yaml.Marshal(obj)
	if err != nil {
		return err
	}

	file, err := os.OpenFile(targetPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, os.ModePerm)
	if err != nil {
		return err
	}
	defer closeFileWithLogError(file)
	if _, err := file.Write(marshalled); err != nil {
		return err
	}
	return nil
}

func addSeparatorToTargetFile(filePath string) error {
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, os.ModePerm)
	if err != nil {
		return err
	}
	defer closeFileWithLogError(file)
	separator := "\n---\n\n"
	if _, err := file.WriteString(separator); err != nil {
		return err
	}
	return nil
}

func closeFileWithLogError(file *os.File) {
	err := file.Close()
	if err != nil {
		klog.Errorf("Error closing file: %v", err)
	}
}
