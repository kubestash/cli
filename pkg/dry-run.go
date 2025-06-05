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
	_ "kubestash.dev/cli/pkg/tree"
)

type dryRunOptions struct {
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

func NewCmdDryRun(clientGetter genericclioptions.RESTClientGetter) *cobra.Command {
	dryRunOpt := &dryRunOptions{}
	cmd := &cobra.Command{
		Use:               "dry-run",
		Short:             `download specific components of a snapshot`,
		Long:              `download specific components of a snapshot from restic repositories`,
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			snapshotName := args[0]

			var err error
			dryRunOpt.restConfig, err = clientGetter.ToRESTConfig()
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

			if err = dryRunOpt.prepareDestinationDir(); err != nil {
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

				return dryRunOpt.runRestoreViaPod(accessorPod, snapshotName)
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
				return dryRunOpt.runRestoreViaPod(&operatorPod, snapshotName)
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
				if len(dryRunOpt.components) != 0 &&
					!slices.Contains(dryRunOpt.components, compName) {
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

				dryRunOpt.resticStats = comp.ResticStats

				// run restore inside docker
				if err = dryRunOpt.runRestoreViaDocker(filepath.Join(DestinationDir, snapshotName, compName), restoreArgs); err != nil {
					return err
				}
				klog.Infof("Component: %v of Snapshot %s/%s restored in path %s", compName, srcNamespace, snapshotName, dryRunOpt.destinationDir)

				for _, resticStat := range dryRunOpt.resticStats {
					err := dryRunOpt.listFilesViaDocker(resticStat.Id) // Using .Id as seen in runRestoreViaDocker
					if err != nil {
						klog.Errorf("Failed to list files: %v", err)
						continue
					}
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&dryRunOpt.destinationDir, "destination", dryRunOpt.destinationDir, "Destination path where components will be restored.")
	cmd.Flags().StringSliceVar(&dryRunOpt.components, "components", dryRunOpt.components, "List of components to restore")
	cmd.Flags().StringSliceVar(&dryRunOpt.exclude, "exclude", dryRunOpt.exclude, "List of pattern for directory/file to ignore during restore")
	cmd.Flags().StringSliceVar(&dryRunOpt.include, "include", dryRunOpt.include, "List of pattern for directory/file to restore")
	cmd.Flags().StringSliceVar(&dryRunOpt.paths, "paths", dryRunOpt.paths, "Gives a random list of paths")
	cmd.Flags().StringVar(&imgRestic.Registry, "docker-registry", imgRestic.Registry, "Docker image registry for restic cli")
	cmd.Flags().StringVar(&imgRestic.Tag, "image-tag", imgRestic.Tag, "Restic docker image tag")

	cmd.MarkFlagsMutuallyExclusive("exclude", "include")

	cmd.Flags().StringVar(&opt.SetupOptions.ScratchDir, "scratch-dir", opt.SetupOptions.ScratchDir, "Temporary directory")
	cmd.Flags().BoolVar(&opt.SetupOptions.EnableCache, "enable-cache", opt.SetupOptions.EnableCache, "Specify whether to enable caching for restic")

	cmd.Flags().StringSliceVar(&dryRunOpt.ANDedLabelSelector, "and-label-selectors", dryRunOpt.ANDedLabelSelector, "A set of labels, all of which need to be matched to filter the resources.")
	cmd.Flags().StringSliceVar(&dryRunOpt.ORedLabelSelector, "or-label-selectors", dryRunOpt.ORedLabelSelector, "A set of labels, a subset of which need to be matched to filter the resources.")

	cmd.Flags().StringSliceVar(&dryRunOpt.IncludeNamespaces, "include-namespaces", dryRunOpt.IncludeNamespaces, "Namespaces to include in backup (comma-separated, e.g., 'default,kube-system')")
	cmd.Flags().StringSliceVar(&dryRunOpt.ExcludeNamespaces, "exclude-namespaces", dryRunOpt.ExcludeNamespaces, "Namespaces to exclude from backup (comma-separated, e.g., 'kube-public,temp')")
	cmd.Flags().StringSliceVar(&dryRunOpt.IncludeResources, "include-resources", dryRunOpt.IncludeResources, "Resource types to include (comma-separated, e.g., 'pods,deployments')")
	cmd.Flags().StringSliceVar(&dryRunOpt.ExcludeResources, "exclude-resources", dryRunOpt.ExcludeResources, "Resource types to exclude (comma-separated, e.g., 'secrets,configmaps')")
	cmd.Flags().BoolVar(&dryRunOpt.IncludeClusterResources, "include-cluster-resources", true, "Specify whether to backup cluster scoped resources")

	return cmd
}

func (opt *dryRunOptions) runRestoreViaPod(pod *core.Pod, snapshotName string) error {
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

func (opt *dryRunOptions) runCmdViaPod(pod *core.Pod, snapshotName string) error {
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

func (opt *dryRunOptions) copyDownloadedDataToDestination(pod *core.Pod) error {
	_, err := exec.Command(CmdKubectl, "cp", fmt.Sprintf("%s/%s:%s", pod.Namespace, pod.Name, SnapshotDownloadDir), opt.destinationDir).CombinedOutput()
	if err != nil {
		return err
	}
	return nil
}

func (opt *dryRunOptions) clearDataFromPod(pod *core.Pod) error {
	cmd := []string{"rm", "-rf", SnapshotDownloadDir}
	_, err := execOnPod(opt.restConfig, pod, cmd)
	return err
}

func (opt *dryRunOptions) prepareDestinationDir() (err error) {
	// if destination flag is not specified, restore in current directory
	if opt.destinationDir == "" {
		if opt.destinationDir, err = os.Getwd(); err != nil {
			return err
		}
	}
	return os.MkdirAll(opt.destinationDir, 0o755)
}

func (opt *dryRunOptions) runRestoreViaDocker(destination string, args []string) error {
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

func (opt *dryRunOptions) getFileContentViaDocker(snapshotID, filePath string) (*unstructured.Unstructured, error) {
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
	klog.Infoln("###Inside the file read from container function\n")
	//klog.Infoln("Running docker with args:", args)
	cmd := exec.Command(CmdDocker, args...)
	dumpOutput, _ := cmd.CombinedOutput()
	klog.Infoln("Output:", string(dumpOutput))
	lines := strings.Split(string(dumpOutput), "\n")
	yamlStart := -1
	for i, line := range lines {
		if strings.HasPrefix(line, "apiVersion:") {
			yamlStart = i
			break
		}
	}
	if yamlStart == -1 {
		log.Fatalf("Could not find start of YAML content in output:\n%s", string(dumpOutput))
	}
	clean := strings.Join(lines[yamlStart:], "\n")
	jsonBytes, err := yaml.YAMLToJSON([]byte(clean))
	if err != nil {
		log.Fatalf("YAMLToJSON failed: %v", err)
	}
	//klog.Infoln("####Output\n", clean)
	return parseBytesToUnstructured(jsonBytes)
}

func (dryRunOpt *dryRunOptions) extractLabels(snapshotID, fileName string) []string {
	unstructuredObject, err := dryRunOpt.getFileContentViaDocker(snapshotID, fileName)
	if err != nil {
		fmt.Printf("Error reading file %s: %s\n", fileName, err)
	}
	//klog.Infoln("###Unstructered Object string dryRun", unstructuredObject)
	return labelsToStrings(unstructuredObject.GetLabels())
}

func (dryRunOpt *dryRunOptions) matchLabels(labels []string) bool {
	return matchesAll(labels, dryRunOpt.ANDedLabelSelector) && matchesAny(labels, dryRunOpt.ORedLabelSelector)
}

func (opt dryRunOptions) shouldShow(snapshotID, file string) bool {
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

func (opt *dryRunOptions) showInTreeFormat(files []string) {
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

func (opt *dryRunOptions) filterFiles(snapshotID string, files []string) []string {
	filteredFiles := []string{}
	for _, file := range files {
		extension := filepath.Ext(file)
		if extension != ".yaml" && extension != ".json" {
			continue
		}
		prefixTrimmedFile := strings.TrimPrefix(file, "/kubestash-tmp/manifest/")
		if prefixTrimmedFile == snapshotID {
			break
		}
		if opt.shouldShow(snapshotID, prefixTrimmedFile) {
			filteredFiles = append(filteredFiles, prefixTrimmedFile)
		}
	}
	return filteredFiles
}

func (opt *dryRunOptions) listFilesViaDocker(snapshotID string) error {
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
	opt.dumpFilteredFilesToLocal(snapshotID, filteredFiles)
	return nil
}

func (opt *dryRunOptions) dumpFilteredFilesToLocal(snapshotID string, files []string) error {
	currentUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("failed to get current user: %v", err)
	}

	for _, file := range files {
		args := []string{
			"run",
			"--rm",
			"-u", currentUser.Uid,
			"-v", ScratchDir + ":" + ScratchDir,
			"--env", fmt.Sprintf("%s=", EnvHttpProxy) + os.Getenv(EnvHttpProxy),
			"--env", fmt.Sprintf("%s=", EnvHttpsProxy) + os.Getenv(EnvHttpsProxy),
			"--env-file", filepath.Join(ConfigDir, ResticEnvs),
			imgRestic.ToContainerImage(),
			"dump", snapshotID, "/kubestash-tmp/manifest/" + file,
		}

		cmd := exec.Command(CmdDocker, args...)
		output, err := cmd.Output()
		if err != nil {
			klog.Errorf("failed to dump file %s: %v", file, err)
			continue
		}

		// Write to destination directory, preserving directory structure
		targetPath := filepath.Join(opt.destinationDir, file)
		if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
			klog.Errorf("failed to create directory for %s: %v", targetPath, err)
			continue
		}

		if err := os.WriteFile(targetPath, output, 0o644); err != nil {
			klog.Errorf("failed to write file %s: %v", targetPath, err)
			continue
		}

		klog.Infof("Downloaded: %s", targetPath)
	}
	return nil
}
