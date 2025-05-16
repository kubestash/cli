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
	"encoding/json"
	"fmt"
	_ "k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"log"
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
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	kmapi "kmodules.xyz/client-go/api/v1"
	v1 "kmodules.xyz/offshoot-api/api/v1"
	storageapi "kubestash.dev/apimachinery/apis/storage/v1alpha1"
	"kubestash.dev/apimachinery/pkg"
	"kubestash.dev/apimachinery/pkg/restic"
	"kubestash.dev/cli/pkg/filter"
	_ "kubestash.dev/cli/pkg/tree"
)

type viewOptions struct {
	restConfig     *rest.Config
	destinationDir string // user provided or, current working dir

	resticStats []storageapi.ResticStats
	components  []string
	exclude     []string
	include     []string
	paths       []string

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

			if err = viewOpt.prepareDestinationDir(); err != nil {
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

				return viewOpt.runRestoreViaPod(accessorPod, snapshotName)
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
				return viewOpt.runRestoreViaPod(&operatorPod, snapshotName)
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

				// run restore inside docker
				if err = viewOpt.runRestoreViaDocker(filepath.Join(DestinationDir, snapshotName, compName), restoreArgs); err != nil {
					return err
				}
				klog.Infof("Component: %v of Snapshot %s/%s restored in path %s", compName, srcNamespace, snapshotName, viewOpt.destinationDir)

				for _, resticStat := range viewOpt.resticStats {
					err := viewOpt.listFilesViaDocker(resticStat.Id) // Using .Id as seen in runRestoreViaDocker
					if err != nil {
						klog.Errorf("Failed to list files: %v", err)
						continue
					}
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&viewOpt.destinationDir, "destination", viewOpt.destinationDir, "Destination path where components will be restored.")
	cmd.Flags().StringSliceVar(&viewOpt.components, "components", viewOpt.components, "List of components to restore")
	cmd.Flags().StringSliceVar(&viewOpt.exclude, "exclude", viewOpt.exclude, "List of pattern for directory/file to ignore during restore")
	cmd.Flags().StringSliceVar(&viewOpt.include, "include", viewOpt.include, "List of pattern for directory/file to restore")
	cmd.Flags().StringSliceVar(&viewOpt.paths, "paths", viewOpt.paths, "Gives a random list of paths")
	cmd.Flags().StringVar(&imgRestic.Registry, "docker-registry", imgRestic.Registry, "Docker image registry for restic cli")
	cmd.Flags().StringVar(&imgRestic.Tag, "image-tag", imgRestic.Tag, "Restic docker image tag")

	cmd.MarkFlagsMutuallyExclusive("exclude", "include")

	cmd.Flags().StringSliceVar(&viewOpt.ANDedLabelSelector, "and-label-selectors", viewOpt.ANDedLabelSelector, "A set of labels, all of which need to be matched to filter the resources.")
	cmd.Flags().StringSliceVar(&viewOpt.ORedLabelSelector, "or-label-selectors", viewOpt.ORedLabelSelector, "A set of labels, a subset of which need to be matched to filter the resources.")

	cmd.Flags().StringSliceVar(&viewOpt.IncludeNamespaces, "include-namespaces", viewOpt.IncludeNamespaces, "Namespaces to include in backup (comma-separated, e.g., 'default,kube-system')")
	cmd.Flags().StringSliceVar(&viewOpt.ExcludeNamespaces, "exclude-namespaces", viewOpt.ExcludeNamespaces, "Namespaces to exclude from backup (comma-separated, e.g., 'kube-public,temp')")
	cmd.Flags().StringSliceVar(&viewOpt.IncludeResources, "include-resources", viewOpt.IncludeResources, "Resource types to include (comma-separated, e.g., 'pods,deployments')")
	cmd.Flags().StringSliceVar(&viewOpt.ExcludeResources, "exclude-resources", viewOpt.ExcludeResources, "Resource types to exclude (comma-separated, e.g., 'secrets,configmaps')")
	cmd.Flags().BoolVar(&viewOpt.IncludeClusterResources, "include-cluster-resources", true, "Specify whether to backup cluster scoped resources")

	return cmd
}

func (opt *viewOptions) runRestoreViaPod(pod *core.Pod, snapshotName string) error {
	if err := opt.runCmdViaPod(pod, snapshotName); err != nil {
		return err
	}

	if err := opt.copyDownloadedDataToDestination(pod); err != nil {
		return err
	}

	if err := opt.clearDataFromPod(pod); err != nil {
		return err
	}

	klog.Infof("Snapshot %s/%s restored in path %s", srcNamespace, snapshotName, opt.destinationDir)
	return nil
}

func (opt *viewOptions) runCmdViaPod(pod *core.Pod, snapshotName string) error {
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

func (opt *viewOptions) copyDownloadedDataToDestination(pod *core.Pod) error {
	_, err := exec.Command(CmdKubectl, "cp", fmt.Sprintf("%s/%s:%s", pod.Namespace, pod.Name, SnapshotDownloadDir), opt.destinationDir).CombinedOutput()
	if err != nil {
		return err
	}
	return nil
}

func (opt *viewOptions) clearDataFromPod(pod *core.Pod) error {
	cmd := []string{"rm", "-rf", SnapshotDownloadDir}
	_, err := execOnPod(opt.restConfig, pod, cmd)
	return err
}

func (opt *viewOptions) prepareDestinationDir() (err error) {
	// if destination flag is not specified, restore in current directory
	if opt.destinationDir == "" {
		if opt.destinationDir, err = os.Getwd(); err != nil {
			return err
		}
	}
	return os.MkdirAll(opt.destinationDir, 0o755)
}

func (opt *viewOptions) runRestoreViaDocker(destination string, args []string) error {
	// get current user
	currentUser, err := user.Current()
	if err != nil {
		return err
	}
	restoreArgs := []string{
		"run",
		"--rm",
		"-u", currentUser.Uid,
		"-v", ScratchDir + ":" + ScratchDir,
		"-v", opt.destinationDir + ":" + DestinationDir,
		"--env", fmt.Sprintf("%s=", EnvHttpProxy) + os.Getenv(EnvHttpProxy),
		"--env", fmt.Sprintf("%s=", EnvHttpsProxy) + os.Getenv(EnvHttpsProxy),
		"--env-file", filepath.Join(ConfigDir, ResticEnvs),
		imgRestic.ToContainerImage(),
	}

	restoreArgs = append(restoreArgs, args...)

	for _, include := range opt.include {
		restoreArgs = append(restoreArgs, "--include")
		restoreArgs = append(restoreArgs, include)
	}

	for _, exclude := range opt.exclude {
		restoreArgs = append(restoreArgs, "--exclude")
		restoreArgs = append(restoreArgs, exclude)
	}

	for _, resticStat := range opt.resticStats {
		rargs := append(restoreArgs, resticStat.Id, "--target", destination)
		klog.Infoln("Running docker with args:", rargs)
		out, err := exec.Command(CmdDocker, rargs...).CombinedOutput()
		klog.Infoln("Output:", string(out))
		if err != nil {
			return err
		}
	}
	return nil
}

func getResourceFromGroupResource(gv string) string {
	parts := strings.Split(gv, ".")
	return parts[0]
}

func parseBytesToUnstructured(byteData []byte) (*unstructured.Unstructured, error) {
	// Convert YAML to JSON (works even if input is JSON)
	jsonData, err := yaml.YAMLToJSON(byteData)
	if err != nil {
		return nil, err
	}

	var obj unstructured.Unstructured
	err = json.Unmarshal(jsonData, &obj)
	if err != nil {
		return nil, err
	}

	return &obj, nil
}

func (opt *viewOptions) getFileContentViaDocker(snapshotID, filePath string) (*unstructured.Unstructured, error) {
	currentUser, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("failed to get current user: %v", err)
	}
	args := []string{
		"run",
		"--rm",
		"-u", currentUser.Uid,
		"-v", ScratchDir + ":" + ScratchDir,
		"--env", fmt.Sprintf("%s=", EnvHttpProxy) + os.Getenv(EnvHttpProxy),
		"--env", fmt.Sprintf("%s=", EnvHttpsProxy) + os.Getenv(EnvHttpsProxy),
		"--env-file", filepath.Join(ConfigDir, ResticEnvs),
		"--env", "RESTIC_CACHE_DIR=" + ScratchDir,
		imgRestic.ToContainerImage(),
		"dump", // dump command to show content of a file
		snapshotID,
		filePath, // file path within the snapshot
	}
	//klog.Infoln("###Inside the file read from container function\n")
	//klog.Infoln("Running docker with args:", args)
	cmd := exec.Command(CmdDocker, args...)
	dumpOutput, _ := cmd.CombinedOutput()
	clean := strings.TrimSpace(string(dumpOutput))
	if clean == "" || !strings.Contains(clean, "apiVersion:") {
		log.Fatalf("dumped content is not valid YAML:\n%s", clean)
	}
	jsonBytes, err := yaml.YAMLToJSON([]byte(clean))
	if err != nil {
		log.Fatalf("YAMLToJSON failed: %v", err)
	}
	//klog.Infoln("####Output\n", clean)
	return parseBytesToUnstructured(jsonBytes)
}

func (viewOpt *viewOptions) extractLabels(snapshotID, fileName string) []string {
	unstructuredObject, err := viewOpt.getFileContentViaDocker(snapshotID, fileName)
	if err != nil {
		fmt.Printf("Error reading file %s: %s\n", fileName, err)
	}
	//klog.Infoln("###Unstructered Object string view", unstructuredObject)
	return labelsToStrings(unstructuredObject.GetLabels())
}

func (viewOpt *viewOptions) matchLabels(labels []string) bool {
	return filter.MatchesAll(labels, viewOpt.ANDedLabelSelector) && filter.MatchesAny(labels, viewOpt.ORedLabelSelector)
}

func labelsToStrings(labels map[string]string) []string {
	out := make([]string, 0, len(labels))
	for k, v := range labels {
		out = append(out, fmt.Sprintf("%s:%s", k, v))
	}
	return out
}

func (opt viewOptions) shouldShow(snapshotID, file string) bool {
	parts := strings.Split(file, "/")
	parts[len(parts)-1] = strings.TrimSuffix(parts[len(parts)-1], filepath.Ext(parts[len(parts)-1]))
	resource := getResourceFromGroupResource(parts[0])
	var namespace string
	if parts[1] == "cluster" {
		namespace = ""
	} else {
		namespace = parts[2]
	}
	passed := false
	if namespace == "" && globalIncludeExclude.ShouldIncludeResource(resource, false) {
		passed = true
	} else if globalIncludeExclude.ShouldIncludeResource(resource, true) && globalIncludeExclude.ShouldIncludeNamespace(namespace) {
		passed = true
	}
	if passed == false {
		return false
	}
	labels := opt.extractLabels(snapshotID, "/kubestash-tmp/manifest/"+file)
	return opt.matchLabels(labels)
}

func (opt *viewOptions) showInTreeFormat(files []string) {
	l := list.NewWriter()
	l.SetStyle(list.StyleConnectedLight) // This gives the ├─ └─ style
	l.AppendItem(".")                    // Root node
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
					l.Indent()
				}
				l.AppendItem(part)
				seen[currentPath] = true
				// Reset indentation
				for lvl := 0; lvl < i; lvl++ {
					l.UnIndent()
				}
			}
			currentPath += "/"
		}
	}
	fmt.Println(l.Render())
}

func (opt *viewOptions) filterFiles(snapshotID string, files []string) []string {
	filteredFiles := []string{}
	for _, file := range files {
		extension := filepath.Ext(file)
		if extension != ".yaml" && extension != ".json" {
			continue
		}
		prefixTrimmedFile := strings.TrimPrefix(file, "/kubestash-tmp/manifest/")
		if opt.shouldShow(snapshotID, prefixTrimmedFile) {
			filteredFiles = append(filteredFiles, prefixTrimmedFile)
		}
	}
	return filteredFiles
}

func (opt *viewOptions) listFilesViaDocker(snapshotID string) error {
	resourceFilter := filter.NewIncludeExclude().Includes(opt.IncludeResources...).Excludes(opt.ExcludeResources...)
	namespaceFilter := filter.NewIncludeExclude().Includes(opt.IncludeNamespaces...).Excludes(opt.ExcludeNamespaces...)
	globalIncludeExclude = filter.NewGlobalIncludeExclude(resourceFilter, namespaceFilter, opt.IncludeClusterResources)

	currentUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("failed to get current user: %v", err)
	}
	args := []string{
		"run",
		"--rm",
		"-u", currentUser.Uid,
		"-v", ScratchDir + ":" + ScratchDir,
		"--env", fmt.Sprintf("%s=", EnvHttpProxy) + os.Getenv(EnvHttpProxy),
		"--env", fmt.Sprintf("%s=", EnvHttpsProxy) + os.Getenv(EnvHttpsProxy),
		"--env-file", filepath.Join(ConfigDir, ResticEnvs),
		imgRestic.ToContainerImage(),
		"ls",
		snapshotID,
	}
	klog.Infoln("Running docker with args:", args)
	cmd := exec.Command(CmdDocker, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		klog.Errorf("docker command failed: %v\nOutput: %s", err, string(output))
		return err
	}
	klog.Infoln("###Docker command output:", string(output))

	files := strings.Split(string(output), "\n")
	filteredFiles := opt.filterFiles(snapshotID, files)
	opt.showInTreeFormat(filteredFiles)

	return nil
}

/*
// Force command registration at init time
func init() {
	// This will print during binary execution if the package loads
	println("DEBUG: view command package initialized")

	// Register a dummy command to ensure compilation
	cobra.AddTemplateFunc("viewCommandDummy", func() string { return "" })
}
/**/
