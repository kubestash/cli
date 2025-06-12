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

/*
import (
	"fmt"
	"k8s.io/klog/v2"
	"kubestash.dev/cli/pkg/filter"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
)

/*
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

	"github.com/spf13/cobra"
	_ "k8s.io/apimachinery/pkg/runtime"
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

	resticStats  []storageapi.ResticStats
	components   []string
	exclude      []string
	include      []string
	paths        []string
	SetupOptions restic.SetupOptions

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

			fmt.Println("Check source namespace: %s", srcNamespace)

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
			/*
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
			/*
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
			            /**/
/*
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
				/*
								if err = dryRunOpt.runRestoreViaDocker(filepath.Join(DestinationDir, snapshotName, compName), restoreArgs); err != nil {
									return err
								}
								klog.Infof("Component: %v of Snapshot %s/%s restored in path %s", compName, srcNamespace, snapshotName, dryRunOpt.destinationDir)

				for _, resticStat := range dryRunOpt.resticStats {
					err := dryRunOpt.listFilesViaDockerThenFilterThenDump(resticStat.Id) // Using .Id as seen in runRestoreViaDocker
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

	cmd.Flags().StringVar(&opt.SetupOptions.ScratchDir, "scratch-dir", dryRunOpt.SetupOptions.ScratchDir, "Temporary directory")
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

func (opt *dryRunOptions) prepareDestinationDir() (err error) {
	// if destination flag is not specified, restore in current directory
	if opt.destinationDir == "" {
		if opt.destinationDir, err = os.Getwd(); err != nil {
			return err
		}
	}
	return os.MkdirAll(opt.destinationDir, 0o755)
}

func (opt *dryRunOptions) extractLabels(yamlStr string) []string {
	unstructuredObject, err := yamlToUnstructured(yamlStr)
	if err != nil {
		fmt.Printf("Error getting unstructured file: %s\n", err)
	}
	//klog.Infoln("###Unstructered Object string view", unstructuredObject)
	return labelsToStrings(unstructuredObject.GetLabels())
}

func (opt *dryRunOptions) matchLabels(labels []string) bool {
	return matchesAll(labels, opt.ANDedLabelSelector) && matchesAny(labels, opt.ORedLabelSelector)
}

func (opt *dryRunOptions) shouldShow(file string) bool {
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
	} else if namespace != "" && globalIncludeExclude.ShouldIncludeResource(resource, true) && globalIncludeExclude.ShouldIncludeNamespace(namespace) {
		passed = true
	}
	return passed
}

func (opt *dryRunOptions) listFilesViaDockerThenFilterThenDump(snapshotID string) error {
	resourceFilter := filter.NewIncludeExclude().Includes(opt.IncludeResources...).Excludes(opt.ExcludeResources...)
	namespaceFilter := filter.NewIncludeExclude().Includes(opt.IncludeNamespaces...).Excludes(opt.ExcludeNamespaces...)
	globalIncludeExclude = filter.NewGlobalIncludeExclude(resourceFilter, namespaceFilter, opt.IncludeClusterResources)

	currentUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("failed to get current user: %v", err)
	}
	containerName := "snapshot-container"
	restoreDir := "/tmp/restore"
	// Check if container exists
	checkCmd := exec.Command(CmdDocker, "ps", "-a", "-f", "name="+containerName, "--format", "{{.Names}}")
	out, err := checkCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to check existing containers: %v", err)
	}
	containerExists := strings.Contains(string(out), containerName)
	// If container doesn't exist, create it
	if !containerExists {
		restoreArgs := []string{
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
		restoreCmd := exec.Command(CmdDocker, restoreArgs...)
		restoreOut, err := restoreCmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to create container: %v\nOutput: %s", err, string(restoreOut))
		}
	}
	// Ensure cleanup: remove the container at the end
	defer func() {
		_ = exec.Command(CmdDocker, "rm", "-f", containerName).Run()
	}()

	// Step 1: Restore snapshot inside container
	restoreSnapshotCmd := exec.Command(
		CmdDocker, "exec", "-u", currentUser.Uid,
		containerName,
		"restic", "restore", snapshotID, "--target", restoreDir,
	)
	restoreOutput, err := restoreSnapshotCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to restore snapshot: %v\nOutput: %s", err, string(restoreOutput))
	}

	// Step 2: List files under /restore inside the container
	findCmd := exec.Command(
		CmdDocker, "exec", "-u", currentUser.Uid,
		containerName,
		"find", restoreDir, "-type", "f", "-name", "*.yaml",
	)
	findOutput, err := findCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to list yaml files: %v\nOutput: %s", err, string(findOutput))
	}
	files := strings.Split(strings.TrimSpace(string(findOutput)), "\n")

	// Step 3: Print each YAML file content
	for _, fullPath := range files {
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
		fmt.Printf("-----\n{filename: %s,\nfilecontent:\n%s \nlabels: %v \n}\n", fullPath, string(content), labels)
		if opt.matchLabels(labels) {
			fullPath = strings.TrimPrefix(fullPath, filepath.Join(restoreDir, "kubestash-tmp/manifest/"))
			if opt.shouldShow(fullPath) {
				// Write to destination directory, preserving directory structure
				targetPath := filepath.Join(opt.destinationDir, snapshotID, opt.destinationDir, fullPath)
				if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
					klog.Errorf("failed to create directory for %s: %v", targetPath, err)
					continue
				}
				if err := os.WriteFile(targetPath, content, 0o644); err != nil {
					klog.Errorf("failed to write file %s: %v", targetPath, err)
					continue
				}
				klog.Infof("Dump Directory: %s", targetPath)
			}
		}
	}
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
		targetPath := filepath.Join(opt.destinationDir, snapshotID, file)
		if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
			klog.Errorf("failed to create directory for %s: %v", targetPath, err)
			continue
		}

		if err := os.WriteFile(
			, output, 0o644); err != nil {
			klog.Errorf("failed to write file %s: %v", targetPath, err)
			continue
		}

		klog.Infof("Dump Directory: %s", targetPath)
	}
	return nil
}


*/
