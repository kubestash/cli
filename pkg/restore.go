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
	core "k8s.io/api/core/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/klog/v2"
	kmapi "kmodules.xyz/client-go/api/v1"
	v1 "kmodules.xyz/offshoot-api/api/v1"
	"kubestash.dev/apimachinery/pkg/restic"
	"kubestash.dev/cli/pkg/common"
	"kubestash.dev/cli/pkg/common/dump"
	_ "kubestash.dev/cli/pkg/filter"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"
)

type options struct {
	*common.Options
}

var (
	masterURL      string
	kubeconfigPath string
	opt            = options{
		Options: common.NewOptions(),
	}
	dumpImplementer *dump.ResourceManager
)

func NewCmdRestore(clientGetter genericclioptions.RESTClientGetter) *cobra.Command {
	cmd := &cobra.Command{
		Use:               "restore",
		Short:             "Restore Kubernetes resources",
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			opt.Config, err = clientGetter.ToRESTConfig()
			if err != nil {
				return err
			}

			opt.Client, err = common.NewRuntimeClient(opt.Config)
			if err != nil {
				return fmt.Errorf("failed to get kubernetes client: %w", err)
			}

			klient = opt.Client

			srcNamespace = opt.Namespace
			//srcNamespace, _, err = clientGetter.ToRawKubeConfigLoader().Namespace()
			if err != nil {
				return err
			}

			fmt.Println("####Check Namespace %s", srcNamespace)

			opt.Snapshot, err = opt.GetSnapshot(kmapi.ObjectReference{
				Name:      opt.SnapshotName,
				Namespace: srcNamespace,
			})
			if err != nil {
				return fmt.Errorf("failed to get snapshot Namespace: %s SnapshotName: %s: Error: %w", opt.Snapshot.Name, err)
			}

			fmt.Println("####Check SnapshotName: %s Namespace: ", opt.Snapshot.Name, opt.Snapshot.Namespace)

			fmt.Println("####Check Snapshot.Spec.Repository: %s ", opt.Snapshot.Spec.Repository)

			repository, err := getRepository(kmapi.ObjectReference{
				Name:      opt.Snapshot.Spec.Repository,
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
				/*
							if backupStorage.Spec.Storage.Local != nil {
								if !backupStorage.LocalNetworkVolume() {
									return fmt.Errorf("unsupported type of local backend provided")
								}
								accessorPod, err := getLocalBackendAccessorPod(repository.Spec.StorageRef)
								if err != nil {
									return err
								}
								if err := opt.runCmdViaPod(accessorPod, opt.SnapshotName); err != nil {
									return err
								}
								contents, err := opt.getContentsViaPod(accessorPod)
								if err != nil {
									return err
								}
								return nil
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
								if err := opt.runCmdViaPod(&operatorPod, opt.SnapshotName); err != nil {
									return err
								}
								contents, err := opt.getContentsViaPod(&operatorPod)
								if err != nil {
									return err
								}
								return nil
							}
				/**/
			if err := opt.prepareDirectories(); err != nil {
				return err
			}
			defer func() {
				if err := os.RemoveAll(ScratchDir); err != nil {
					klog.Errorf("failed to remove scratch dir. Reason: %v", err)
				}
				if err := os.RemoveAll(opt.DataDir); err != nil {
					klog.Errorf("failed to remove data dir. Reason: %v", err)
				}
			}()

			opt.SetupOptions = restic.SetupOptions{
				Client:     opt.Client,
				ScratchDir: ScratchDir,
				Backends: []*restic.Backend{
					{
						Repository:       repository.Name,
						BackupStorage:    &repository.Spec.StorageRef,
						EncryptionSecret: repository.Spec.EncryptionSecret,
					},
				},
			}

			fmt.Println("####Check DataDir: %v", opt.DataDir)

			// apply nice, ionice settings from env
			opt.SetupOptions.Nice, err = v1.NiceSettingsFromEnv()
			if err != nil {
				return fmt.Errorf("failed to set nice settings: %w", err)
			}
			opt.SetupOptions.IONice, err = v1.IONiceSettingsFromEnv()
			if err != nil {
				return fmt.Errorf("failed to set ionice settings: %w", err)
			}

			for compName, comp := range opt.Snapshot.Status.Components {
				if len(opt.Components) != 0 &&
					!slices.Contains(opt.Components, compName) {
					continue
				}

				opt.SetupOptions.Backends[0].Directory = filepath.Join(repository.Spec.Path, comp.Path)

				w, err := restic.NewResticWrapper(&opt.SetupOptions)
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

				opt.ResticStats = comp.ResticStats
				/*
					if err := os.MkdirAll(filepath.Join(DestinationDir, opt.SnapshotName, compName), 0o755); err != nil {
						return fmt.Errorf("failed to create snapshot directory: %w", err)
					}
				*/

				err = opt.runRestoreViaDocker(filepath.Join(DestinationDir, opt.SnapshotName, compName), restoreArgs)
				if err != nil {
					return err
				}
			}

			if err := opt.setupDumpImplementer(); err != nil {
				return fmt.Errorf("failed to setup dump implementer: %w", err)
			}

			if err = opt.performRestore(); err != nil {
				opt.UpsertRestoreComponentStatus(nil, err)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&masterURL, "master", masterURL, "The address of the Kubernetes API server (overrides any value in kubeconfig)")
	cmd.Flags().StringVar(&kubeconfigPath, "kubeconfig", kubeconfigPath, "Path to kubeconfig file with authorization information (the master location is set by the master flag)")

	cmd.Flags().StringSliceVar(&opt.Components, "components", opt.Components, "List of components to restore")
	cmd.Flags().StringSliceVar(&opt.Exclude, "exclude", opt.Exclude, "List of pattern for directory/file to ignore during restore")
	cmd.Flags().StringSliceVar(&opt.Include, "include", opt.Include, "List of pattern for directory/file to restore")
	cmd.Flags().StringSliceVar(&opt.Paths, "paths", opt.Paths, "Gives a random list of paths")

	//cmd.Flags().StringVar(&opt.Namespace, "namespace", "default", "Namespace of the RestoreSession")
	cmd.Flags().StringVar(&opt.TargetNamespace, "target-namespace", "default", "Namespace where the resources will be restored")
	cmd.Flags().StringVar(&opt.SnapshotName, "snapshot", "", "Name of the snapshot")

	cmd.Flags().StringVar(&opt.DataDir, "data-dir", opt.DataDir, "Local directory where snapshot data will be downloaded and will be deleted")
	cmd.Flags().StringVar(&opt.DryRunDir, "dry-run-dir", opt.DryRunDir, "Local directory where snapshot data will be downloaded for dry run")

	cmd.Flags().StringVar(&opt.SetupOptions.ScratchDir, "scratch-dir", opt.SetupOptions.ScratchDir, "Temporary directory")
	cmd.Flags().BoolVar(&opt.SetupOptions.EnableCache, "enable-cache", opt.SetupOptions.EnableCache, "Specify whether to enable caching for restic")

	cmd.Flags().StringSliceVar(&opt.IncludeNamespaces, "include-namespaces", opt.IncludeNamespaces, "Namespaces to include in restore (comma-separated, e.g., 'default,kube-system')")
	cmd.Flags().StringSliceVar(&opt.ExcludeNamespaces, "exclude-namespaces", opt.ExcludeNamespaces, "Namespaces to exclude from restore (comma-separated, e.g., 'kube-public,temp')")
	cmd.Flags().StringSliceVar(&opt.IncludeResources, "include-resources", opt.IncludeResources, "Resource types to include (comma-separated, e.g., 'pods,deployments')")
	cmd.Flags().StringSliceVar(&opt.ExcludeResources, "exclude-resources", opt.ExcludeResources, "Resource types to exclude (comma-separated, e.g., 'secrets,configmaps')")
	cmd.Flags().StringSliceVar(&opt.ANDedLabelSelector, "and-label-selectors", opt.ANDedLabelSelector, "A set of labels, all of which need to be matched to filter the resources.")
	cmd.Flags().StringSliceVar(&opt.ORedLabelSelector, "or-label-selectors", opt.ORedLabelSelector, "A set of labels, a subset of which need to be matched to filter the resources.")

	cmd.Flags().BoolVar(&opt.IncludeClusterResources, "include-cluster-resources", false, "Specify whether to restore cluster scoped resources")
	cmd.Flags().BoolVar(&opt.OverrideResources, "override-resources", false, "Specify whether to override resources while restoring")

	cmd.Flags().StringVar(&opt.StorageClassMappingsStr, "storage-class-mappings", "", "Mapping of old to new storage classes (e.g., 'old1=new1,old2=new2')")
	cmd.Flags().BoolVar(&opt.RestorePVs, "restore-pvs", false, "Specify whether to restore PersistentVolumes")

	return cmd
}

func (opt *options) performRestore() error {
	/*
		w, err := opt.GetResticWrapperForSnapshots(*opt.Snapshot)
		if err != nil {
			return fmt.Errorf("failed to initiate restic wrapper: %w", err)
		}
		opt.RestoreOptions.Snapshots, err = opt.GetResticSnapshotIDs()
		if err != nil {
			return err
		}

		fmt.Println("Running restic restore...")
		_, err = w.RunRestore(opt.Snapshot.Spec.Repository, opt.RestoreOptions)
		if err != nil {
			return err
		}
		fmt.Println("Restic restore completed.")
	    /**/
	if dumpImplementer == nil {
		return fmt.Errorf("dumpImplementer is nil")
	}

	fmt.Println("Calling RestoreManifests...")
	if err := dumpImplementer.RestoreManifests(context.Background()); err != nil {
		return fmt.Errorf("failed to restore manifests: %w", err)
	}
	fmt.Println("RestoreManifests completed.")

	return nil
}

func (opt *options) setupDumpImplementer() error {
	var err error
	dumpImplementer, err = dump.NewResourceManager(opt.Options)
	return err
}

func (opt *options) prepareDirectories() (err error) {
	// if destination flag is not specified, restore in current directory
	if err = os.MkdirAll(ScratchDir, 0o755); err != nil {
		return err
	}
	if opt.DataDir == "" {
		if err = os.MkdirAll(DestinationDir, 0o755); err != nil {
			return err
		}
	} else if err := os.MkdirAll(opt.DataDir, 0755); err != nil {
		return fmt.Errorf("failed to create data dir: %w", err)
	}
	if opt.DryRunDir != "" {
		if err := os.MkdirAll(opt.DryRunDir, 0755); err != nil {
			return fmt.Errorf("error while creating dry run directory: %w", err)
		}
	}
	return nil
}

func (opt *options) runCmdViaPod(pod *core.Pod, snapshotName string) error {
	command := []string{
		"/kubestash",
		"download", snapshotName,
		"--namespace", srcNamespace,
		"--destination", SnapshotDownloadDir,
	}
	if len(opt.Components) != 0 {
		command = append(command, []string{"--components", strings.Join(opt.Components, ",")}...)
	}
	if len(opt.Exclude) != 0 {
		command = append(command, []string{"--exclude", strings.Join(opt.Exclude, ",")}...)
	}
	if len(opt.Include) != 0 {
		command = append(command, []string{"--include", strings.Join(opt.Include, ",")}...)
	}
	out, err := execOnPod(opt.Config, pod, command)
	if err != nil {
		return err
	}
	klog.Infoln("Output:", out)
	return nil
}

/*
	func (opt *options) getContentsViaPod(pod *core.Pod) ([]os.FileInfo, error) {
		findCmd := []string{
			"find", SnapshotDownloadDir, "-type", "f", "-name", "*.yaml",
		}
		out, err := execOnPod(opt.Config, pod, findCmd)
		if err != nil {
			return nil, fmt.Errorf("failed to list yaml files in pod: %v\nOutput: %s", err, out)
		}
		files := strings.Split(strings.TrimSpace(out), "\n")

		fileInfos := []os.FileInfo
		for _, fullPath := range files {
			if strings.TrimSpace(fullPath) == "" {
				continue
			}
			catCmd := []string{"cat", fullPath}
			content, err := execOnPod(opt.Config, pod, catCmd)
			if err != nil {
				fmt.Printf("WARN: failed to read file %s: %v\nOutput: %s\n", fullPath, err, content)
				continue
			}
			fileInfos = append(fileInfos, content)
		}

		return filteredFiles, nil
	}

/*
*/
func (opt *options) runRestoreViaDocker(destination string, args []string) error {
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
		"-v", opt.DataDir + ":" + DestinationDir,
		"--env", fmt.Sprintf("%s=", EnvHttpProxy) + os.Getenv(EnvHttpProxy),
		"--env", fmt.Sprintf("%s=", EnvHttpsProxy) + os.Getenv(EnvHttpsProxy),
		"--env-file", filepath.Join(ConfigDir, ResticEnvs),
		imgRestic.ToContainerImage(),
	}

	restoreArgs = append(restoreArgs, args...)

	for _, include := range opt.Include {
		restoreArgs = append(restoreArgs, "--include")
		restoreArgs = append(restoreArgs, include)
	}

	for _, exclude := range opt.Exclude {
		restoreArgs = append(restoreArgs, "--exclude")
		restoreArgs = append(restoreArgs, exclude)
	}

	for _, resticStat := range opt.ResticStats {
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
