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
	_ "bufio"
	"fmt"
	_ "k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"kubestash.dev/cli/pkg/filter"
	_ "log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strings"

	_ "encoding/json"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	_ "k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/yaml"

	"github.com/jedib0t/go-pretty/v6/list"
	"github.com/spf13/cobra"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	kmapi "kmodules.xyz/client-go/api/v1"
	v1 "kmodules.xyz/offshoot-api/api/v1"
	storageapi "kubestash.dev/apimachinery/apis/storage/v1alpha1"
	"kubestash.dev/apimachinery/pkg"
	"kubestash.dev/apimachinery/pkg/restic"
	"kubestash.dev/cli/pkg/common"
)

type viewOptions struct {
	restConfig     *rest.Config
	destinationDir string // user provided or, current working dir
	dataDir        string

	SetupOptions restic.SetupOptions
	resticStats  []storageapi.ResticStats
	components   []string
	exclude      []string
	include      []string
	paths        []string

	IncludeNamespaces       []string
	IncludeResources        []string
	ExcludeNamespaces       []string
	ExcludeResources        []string
	IncludeClusterResources bool

	ANDedLabelSelector []string
	ORedLabelSelector  []string
}

type TreeNode struct {
	Name     string
	Children map[string]*TreeNode
}

var globalIncludeExclude *filter.GlobalIncludeExclude

func NewCmdView(clientGetter genericclioptions.RESTClientGetter) *cobra.Command {
	viewOpt := &viewOptions{}
	cmd := &cobra.Command{
		Use:               "view",
		Short:             `view components of a snapshot`,
		Long:              `view components of a snapshot from restic repositories`,
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			snapshotName := args[0]

			var err error
			viewOpt.restConfig, err = clientGetter.ToRESTConfig()
			if err != nil {
				return fmt.Errorf("failed to read kubeconfig. Reason: %v", err)
			}

			srcNamespace, _, err = clientGetter.ToRawKubeConfigLoader().Namespace()
			if err != nil {
				return err
			}

			klient, err = pkg.NewUncachedClient()
			if err != nil {
				return err
			}

			snapshot, err := getSnapshot(kmapi.ObjectReference{
				Name:      snapshotName,
				Namespace: srcNamespace,
			})
			if err != nil {
				return err
			}

			repository, err := getRepository(kmapi.ObjectReference{
				Name:      snapshot.Spec.Repository,
				Namespace: srcNamespace,
			})
			if err != nil {
				return err
			}

			backupStorage, err := getBackupStorage(kmapi.ObjectReference{
				Name:      repository.Spec.StorageRef.Name,
				Namespace: repository.Spec.StorageRef.Namespace,
			})
			if err != nil {
				return err
			}

			if backupStorage.Spec.Storage.Local != nil {
				if !backupStorage.LocalNetworkVolume() {
					return fmt.Errorf("unsupported type of local backend provided")
				}
				accessorPod, err := getLocalBackendAccessorPod(repository.Spec.StorageRef)
				if err != nil {
					return err
				}
				if err := viewOpt.runCmdViaPod(accessorPod, snapshotName); err != nil {
					return err
				}
				files, err := viewOpt.listFilesViaPodThenFilter(accessorPod, snapshot)
				if err != nil {
					return err
				}
				viewOpt.showInTreeFormat(files)
				return viewOpt.clearDataFromPod(accessorPod)
			}

			operatorPod, err := getOperatorPod()
			if err != nil {
				return err
			}
			yes, err := isWorkloadIdentity(operatorPod)
			if err != nil {
				return err
			}
			if yes {
				if err := viewOpt.runCmdViaPod(&operatorPod, snapshotName); err != nil {
					return err
				}
				files, err := viewOpt.listFilesViaPodThenFilter(&operatorPod, snapshot)
				if err != nil {
					return err
				}
				viewOpt.showInTreeFormat(files)
				return viewOpt.clearDataFromPod(&operatorPod)
			}

			if err = os.MkdirAll(ScratchDir, 0o755); err != nil {
				return err
			}
			defer func() {
				err := os.RemoveAll(ScratchDir)
				if err != nil {
					klog.Errorf("failed to remove scratch dir. Reason: %v", err)
				}
			}()
			setupOptions := &restic.SetupOptions{
				Client:     klient,
				ScratchDir: ScratchDir,
				Backends: []*restic.Backend{
					{
						Repository:       repository.Name,
						BackupStorage:    &repository.Spec.StorageRef,
						EncryptionSecret: repository.Spec.EncryptionSecret,
					},
				},
			}
			// apply nice, ionice settings from env
			setupOptions.Nice, err = v1.NiceSettingsFromEnv()
			if err != nil {
				return fmt.Errorf("failed to set nice settings: %w", err)
			}
			setupOptions.IONice, err = v1.IONiceSettingsFromEnv()
			if err != nil {
				return fmt.Errorf("failed to set ionice settings: %w", err)
			}

			for compName, comp := range snapshot.Status.Components {
				if len(viewOpt.components) != 0 &&
					!slices.Contains(viewOpt.components, compName) {
					continue
				}

				setupOptions.Backends[0].Directory = filepath.Join(repository.Spec.Path, comp.Path)
				w, err := restic.NewResticWrapper(setupOptions)
				if err != nil {
					return err
				}
				// dump restic's environments into `restic-env` file.
				// we will pass this env file to restic docker container.
				err = w.DumpEnv(repository.Name, ConfigDir, ResticEnvs)
				if err != nil {
					return err
				}
				restoreArgs := []string{
					"restore",
					"--cache-dir",
					ScratchDir,
				}
				// For TLS secured Minio/REST server, specify cert path
				if w.GetCaPath(repository.Name) != "" {
					restoreArgs = append(restoreArgs, "--cacert", w.GetCaPath(repository.Name))
				}
				viewOpt.resticStats = comp.ResticStats
				files, err := viewOpt.listFilesViaDockerThenFilter(restoreArgs)

				viewOpt.showInTreeFormat(files)
			}

			return nil
		},
	}

	cmd.Flags().StringSliceVar(&viewOpt.components, "components", viewOpt.components, "List of components to restore")
	cmd.Flags().StringSliceVar(&viewOpt.exclude, "exclude", viewOpt.exclude, "List of pattern for directory/file to ignore during restore")
	cmd.Flags().StringSliceVar(&viewOpt.include, "include", viewOpt.include, "List of pattern for directory/file to restore")
	cmd.Flags().StringSliceVar(&viewOpt.paths, "paths", viewOpt.paths, "Gives a random list of paths")
	cmd.Flags().StringVar(&imgRestic.Registry, "docker-registry", imgRestic.Registry, "Docker image registry for restic cli")
	cmd.Flags().StringVar(&imgRestic.Tag, "image-tag", imgRestic.Tag, "Restic docker image tag")

	cmd.MarkFlagsMutuallyExclusive("exclude", "include")

	cmd.Flags().StringVar(&viewOpt.SetupOptions.ScratchDir, "scratch-dir", viewOpt.SetupOptions.ScratchDir, "Temporary directory")
	cmd.Flags().BoolVar(&viewOpt.SetupOptions.EnableCache, "enable-cache", viewOpt.SetupOptions.EnableCache, "Specify whether to enable caching for restic")

	cmd.Flags().StringSliceVar(&viewOpt.ANDedLabelSelector, "and-label-selectors", viewOpt.ANDedLabelSelector, "A set of labels, all of which need to be matched to filter the resources.")
	cmd.Flags().StringSliceVar(&viewOpt.ORedLabelSelector, "or-label-selectors", viewOpt.ORedLabelSelector, "A set of labels, a subset of which need to be matched to filter the resources.")

	cmd.Flags().StringSliceVar(&viewOpt.IncludeNamespaces, "include-namespaces", viewOpt.IncludeNamespaces, "Namespaces to include in backup (comma-separated, e.g., 'default,kube-system')")
	cmd.Flags().StringSliceVar(&viewOpt.ExcludeNamespaces, "exclude-namespaces", viewOpt.ExcludeNamespaces, "Namespaces to exclude from backup (comma-separated, e.g., 'kube-public,temp')")
	cmd.Flags().StringSliceVar(&viewOpt.IncludeResources, "include-resources", viewOpt.IncludeResources, "Resource types to include (comma-separated, e.g., 'pods,deployments')")
	cmd.Flags().StringSliceVar(&viewOpt.ExcludeResources, "exclude-resources", viewOpt.ExcludeResources, "Resource types to exclude (comma-separated, e.g., 'secrets,configmaps')")
	cmd.Flags().BoolVar(&viewOpt.IncludeClusterResources, "include-cluster-resources", true, "Specify whether to backup cluster scoped resources")

	return cmd
}

func (opt *viewOptions) runCmdViaPod(pod *core.Pod, snapshotName string) error {
	if err := os.MkdirAll(SnapshotDownloadDir, 0o755); err != nil {
		return err
	}
	command := []string{
		"/kubestash",
		"download", snapshotName,
		"--namespace", srcNamespace,
		"--destination", SnapshotDownloadDir,
	}
	if len(opt.components) != 0 {
		command = append(command, []string{"--components", strings.Join(opt.components, ",")}...)
	}
	if len(opt.exclude) != 0 {
		command = append(command, []string{"--exclude", strings.Join(opt.exclude, ",")}...)
	}
	if len(opt.include) != 0 {
		command = append(command, []string{"--include", strings.Join(opt.include, ",")}...)
	}
	out, err := execOnPod(opt.restConfig, pod, command)
	if err != nil {
		return err
	}
	klog.Infoln("Output:", out)
	return nil
}

func (opt *viewOptions) clearDataFromPod(pod *core.Pod) error {
	cmd := []string{"rm", "-rf", SnapshotDownloadDir}
	_, err := execOnPod(opt.restConfig, pod, cmd)
	return err
}

func (opt *viewOptions) listFilesViaPodThenFilter(pod *core.Pod, snapshot *storageapi.Snapshot) ([]string, error) {
	resourceFilter := filter.NewIncludeExclude().Includes(opt.IncludeResources...).Excludes(opt.ExcludeResources...)
	namespaceFilter := filter.NewIncludeExclude().Includes(opt.IncludeNamespaces...).Excludes(opt.ExcludeNamespaces...)
	globalIncludeExclude = filter.NewGlobalIncludeExclude(resourceFilter, namespaceFilter, opt.IncludeClusterResources)

	filteredFiles := []string{}
	for componentName, component := range snapshot.Status.Components {
		for _, resticStat := range component.ResticStats {

			findCmd := []string{
				"find", filepath.Join(SnapshotDownloadDir, snapshot.Name, componentName, resticStat.HostPath), "-type", "f", "-name", "*.yaml",
			}
			out, err := execOnPod(opt.restConfig, pod, findCmd)
			if err != nil {
				return nil, fmt.Errorf("failed to list yaml files in pod: %v\nOutput: %s", err, out)
			}

			files := strings.Split(strings.TrimSpace(out), "\n")
			for _, fullPath := range files {
				if strings.TrimSpace(fullPath) == "" {
					continue
				}
				catCmd := []string{"cat", fullPath}
				content, err := execOnPod(opt.restConfig, pod, catCmd)
				if err != nil {
					fmt.Printf("WARN: failed to read file %s: %v\nOutput: %s\n", fullPath, err, content)
					continue
				}
				labels := opt.extractLabels(content)
				if opt.matchLabels(labels) {
					relativePath := strings.TrimPrefix(fullPath, filepath.Join(SnapshotDownloadDir, snapshot.Name, componentName, resticStat.HostPath))
					if opt.shouldShow(relativePath) {
						filteredFiles = append(filteredFiles, filepath.Join(resticStat.HostPath, relativePath))
					}
				}
			}
		}
	}

	return filteredFiles, nil
}

func getResourceFromGroupResource(gv string) string {
	parts := strings.Split(gv, ".")
	return parts[0]
}

func yamlToUnstructured(yamlStr string) (*unstructured.Unstructured, error) {
	jsonData, err := yaml.YAMLToJSON([]byte(yamlStr))
	if err != nil {
		return nil, fmt.Errorf("failed to convert YAML to JSON: %w", err)
	}

	obj := &unstructured.Unstructured{}
	err = obj.UnmarshalJSON(jsonData)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON into unstructured: %w", err)
	}
	return obj, nil
}

func (viewOpt *viewOptions) extractLabels(yamlStr string) []string {
	unstructuredObject, err := yamlToUnstructured(yamlStr)
	if err != nil {
		fmt.Printf("Error getting unstructured file: %s\n", err)
	}
	return labelsToStrings(unstructuredObject.GetLabels())
}

func (viewOpt *viewOptions) matchLabels(labels []string) bool {
	return matchesAll(labels, viewOpt.ANDedLabelSelector) && matchesAny(labels, viewOpt.ORedLabelSelector)
}

func matchesAny(labels, selectors []string) bool {
	if len(selectors) == 0 {
		return true
	}
	set := sets.NewString(labels...)
	for _, sel := range selectors {
		if set.Has(sel) {
			return true
		}
	}
	return false
}

func matchesAll(labels, selectors []string) bool {
	if len(selectors) == 0 {
		return true
	}
	set := sets.NewString(labels...)
	for _, sel := range selectors {
		if !set.Has(sel) {
			return false
		}
	}
	return true
}

func labelsToStrings(labels map[string]string) []string {
	out := make([]string, 0, len(labels))
	for k, v := range labels {
		out = append(out, fmt.Sprintf("%s:%s", k, v))
	}
	return out
}

func (opt viewOptions) shouldShow(file string) bool {
	parts := strings.Split(file, "/")
	parts[len(parts)-1] = strings.TrimSuffix(parts[len(parts)-1], filepath.Ext(parts[len(parts)-1]))
	resource := getResourceFromGroupResource(parts[0])
	var namespace string
	if parts[1] == common.ClusterScopedDir {
		namespace = ""
	} else {
		namespace = parts[2]
	}
	passed := false
	if namespace == "" && globalIncludeExclude.ShouldIncludeResource(resource, false) {
		passed = true
	} else if namespace != "" && globalIncludeExclude.ShouldIncludeResource(resource, true) && globalIncludeExclude.ShouldIncludeNamespace(namespace) {
		passed = true
	}
	return passed
}

func (opt *viewOptions) showInTreeFormat(files []string) {
	List := list.NewWriter()
	List.SetStyle(list.StyleConnectedLight) // This gives the ├─ └─ style
	List.AppendItem(".")                    // Root node
	seen := make(map[string]bool)
	for _, file := range files {
		extension := filepath.Ext(file)
		if extension != ".yaml" && extension != ".json" {
			continue
		}
		parts := strings.Split(file, "/")
		currentPath := ""
		for i, part := range parts {
			currentPath += part
			if !seen[currentPath] {
				// Set indentation level
				for lvl := 0; lvl < i; lvl++ {
					List.Indent()
				}
				List.AppendItem(part)
				seen[currentPath] = true
				// Reset indentation
				for lvl := 0; lvl < i; lvl++ {
					List.UnIndent()
				}
			}
			currentPath += "/"
		}
	}
	fmt.Println(List.Render())
}

func (opt *viewOptions) listFilesViaDockerThenFilter(args []string) ([]string, error) {
	resourceFilter := filter.NewIncludeExclude().Includes(opt.IncludeResources...).Excludes(opt.ExcludeResources...)
	namespaceFilter := filter.NewIncludeExclude().Includes(opt.IncludeNamespaces...).Excludes(opt.ExcludeNamespaces...)
	globalIncludeExclude = filter.NewGlobalIncludeExclude(resourceFilter, namespaceFilter, opt.IncludeClusterResources)

	currentUser, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("failed to get current user: %v", err)
	}

	containerName := "snapshot-container"
	restoreDir := "/tmp/restore"

	// Check if container exists
	checkCmd := exec.Command(CmdDocker, "ps", "-a", "-f", "name="+containerName, "--format", "{{.Names}}")
	out, err := checkCmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to check existing containers: %v", err)
	}
	containerExists := strings.Contains(string(out), containerName)
	if !containerExists {
		baseArgs := []string{
			"run", "-d",
			"--name", containerName,
			"-u", currentUser.Uid,
			"--env", fmt.Sprintf("%s=%s", EnvHttpProxy, os.Getenv(EnvHttpProxy)),
			"--env", fmt.Sprintf("%s=%s", EnvHttpsProxy, os.Getenv(EnvHttpsProxy)),
			"--env-file", filepath.Join(ConfigDir, ResticEnvs),
			"--entrypoint", "sh",
			imgRestic.ToContainerImage(),
			"-c", "sleep infinity",
		}

		klog.Infoln("Creating container:", containerName)
		klog.Infoln("Running command:", baseArgs)
		runOut, err := exec.Command(CmdDocker, baseArgs...).CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("failed to create container: %v\nOutput: %s", err, string(runOut))
		}
	}
	defer func() {
		_ = exec.Command(CmdDocker, "rm", "-f", containerName).Run()
	}()

	for _, resticStat := range opt.resticStats {
		restoreCmd := []string{
			"exec", "-u", currentUser.Uid,
			containerName,
			"restic",
		}
		restoreCmd = append(restoreCmd, args...)
		restoreCmd = append(restoreCmd, resticStat.Id)
		for _, include := range opt.include {
			restoreCmd = append(restoreCmd, "--include", include)
		}
		for _, exclude := range opt.exclude {
			restoreCmd = append(restoreCmd, "--exclude", exclude)
		}
		restoreCmd = append(restoreCmd, "--target", restoreDir)
		//klog.Infof("Running docker command: docker %v", restoreCmd)
		output, err := exec.Command(CmdDocker, restoreCmd...).CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("failed to restore snapshot: %v\nOutput: %s", err, string(output))
		}
		fmt.Println("Restored:", string(output))
	}

	filteredFiles := []string{}
	for _, resticStat := range opt.resticStats {
		findFilePathsCmd := exec.Command(
			CmdDocker, "exec", "-u", currentUser.Uid,
			containerName,
			"find", filepath.Join(restoreDir, resticStat.HostPath), "-type", "f", "-name", "*.yaml",
		)
		findOutput, err := findFilePathsCmd.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("failed to list yaml files: %v\nOutput: %s", err, string(findOutput))
		}
		filePaths := strings.Split(strings.TrimSpace(string(findOutput)), "\n")
		for _, fullPath := range filePaths {
			if strings.TrimSpace(fullPath) == "" {
				continue
			}
			catCmd := exec.Command(
				CmdDocker, "exec", "-u", currentUser.Uid,
				containerName,
				"cat", fullPath,
			)
			content, err := catCmd.CombinedOutput()
			if err != nil {
				fmt.Printf("WARN: failed to read file %s: %v\nOutput: %s\n", fullPath, err, string(content))
				continue
			}

			labels := opt.extractLabels(string(content))
			if opt.matchLabels(labels) {
				relativePath := strings.TrimPrefix(fullPath, filepath.Join(restoreDir, resticStat.HostPath))
				if opt.shouldShow(relativePath) {
					filteredFiles = append(filteredFiles, filepath.Join(resticStat.HostPath, relativePath))
				}
			}
		}
	}

	return filteredFiles, nil
}
