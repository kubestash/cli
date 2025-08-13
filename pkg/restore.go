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
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	core "k8s.io/api/core/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/klog/v2"
	kmapi "kmodules.xyz/client-go/api/v1"
	v1 "kmodules.xyz/offshoot-api/api/v1"
	"kubestash.dev/apimachinery/pkg/restic"
	"kubestash.dev/cli/pkg/common"
	"kubestash.dev/cli/pkg/common/dump"
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

func NewCmdManifestRestore(clientGetter genericclioptions.RESTClientGetter) *cobra.Command {
	cmd := &cobra.Command{
		Use:               "manifest-restore",
		Short:             "Restore Kubernetes resources",
		Long:              "Restore Kubernetes resources from snapshot",
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

			if err != nil {
				return err
			}

			opt.Snapshot, err = opt.GetSnapshot(kmapi.ObjectReference{
				Name:      opt.SnapshotName,
				Namespace: srcNamespace,
			})
			if err != nil {
				return fmt.Errorf("failed to get snapshot Namespace: %s SnapshotName: %s: Error: %w", opt.Namespace, opt.Snapshot.Name, err)
			}

			repository, err := getRepository(kmapi.ObjectReference{
				Name:      opt.Snapshot.Spec.Repository,
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

			if err := opt.prepareDirectories(); err != nil {
				return err
			}
			defer func() {
				if err := common.ClearDir(ScratchDir); err != nil {
					klog.Errorf("failed to remove scratch dir. Reason: %v", err)
				}
				if err := common.ClearDir(opt.DataDir); err != nil {
					klog.Errorf("failed to remove data dir. Reason: %v", err)
				}
			}()

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
				if err := opt.runRestoreViaPod(accessorPod, opt.SnapshotName); err != nil {
					return err
				}
				if err := opt.setupDumpImplementer(); err != nil {
					return fmt.Errorf("failed to setup dump implementer: %w", err)
				}

				if err = opt.performRestore(); err != nil {
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
				if err := opt.runRestoreViaPod(&operatorPod, opt.SnapshotName); err != nil {
					return err
				}
				if err := opt.setupDumpImplementer(); err != nil {
					return fmt.Errorf("failed to setup dump implementer: %w", err)
				}

				if err = opt.performRestore(); err != nil {
					return err
				}
				return nil
			}

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

				err = opt.runRestoreViaDocker(filepath.Join(DestinationDir, opt.SnapshotName, compName), restoreArgs)
				if err != nil {
					return err
				}
			}

			if err := opt.setupDumpImplementer(); err != nil {
				return fmt.Errorf("failed to setup dump implementer: %w", err)
			}

			if err = opt.performRestore(); err != nil {
				return err
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

	cmd.Flags().StringVar(&opt.Namespace, "namespace", "default", "Namespace of the snapshot")
	cmd.Flags().StringVar(&opt.TargetNamespace, "target-namespace", "default", "Namespace where the resources will be restored")
	cmd.Flags().StringVar(&opt.SnapshotName, "snapshot", "", "Name of the snapshot")

	cmd.Flags().StringVar(&opt.DataDir, "data-dir", opt.DataDir, "Temporary local directory where snapshot data will be downloaded and will be deleted")
	cmd.Flags().StringVar(&opt.DryRunDir, "dry-run-dir", opt.DryRunDir, "Local directory where snapshot data will be downloaded for dry run")
	cmd.Flags().UintVar(&opt.MaxIterations, "max-iterations", uint(5), "Maximum number of iterations in restore process")

	cmd.Flags().StringVar(&opt.SetupOptions.ScratchDir, "scratch-dir", opt.SetupOptions.ScratchDir, "Temporary directory")
	cmd.Flags().BoolVar(&opt.SetupOptions.EnableCache, "enable-cache", opt.SetupOptions.EnableCache, "Specify whether to enable caching for restic")

	cmd.Flags().StringSliceVar(&opt.IncludeNamespaces, "include-namespaces", opt.IncludeNamespaces, "Namespaces to include in restore (comma-separated, e.g., 'default,kube-system')")
	cmd.Flags().StringSliceVar(&opt.ExcludeNamespaces, "exclude-namespaces", opt.ExcludeNamespaces, "Namespaces to exclude from restore (comma-separated, e.g., 'kube-public,temp')")
	cmd.Flags().StringSliceVar(&opt.IncludeResources, "include-resources", opt.IncludeResources, "Resource types to include (comma-separated, e.g., 'pods,deployments')")
	cmd.Flags().StringSliceVar(&opt.ExcludeResources, "exclude-resources", opt.ExcludeResources, "Resource types to exclude (comma-separated, e.g., 'secrets,configmaps')")
	cmd.Flags().StringSliceVar(&opt.ANDedLabelSelectors, "and-label-selectors", opt.ANDedLabelSelectors, "A set of labels, all of which need to be matched to filter the resources (comma-separated, e.g., 'key1:value1,key2:value2')")
	cmd.Flags().StringSliceVar(&opt.ORedLabelSelectors, "or-label-selectors", opt.ORedLabelSelectors, "A set of labels, a subset of which need to be matched to filter the resources (comma-separated, e.g., 'key1:value1,key2:value2')")

	cmd.Flags().BoolVar(&opt.IncludeClusterResources, "include-cluster-resources", false, "Specify whether to restore cluster scoped resources")
	cmd.Flags().BoolVar(&opt.OverrideResources, "override-resources", false, "Specify whether to override resources while restoring")

	cmd.Flags().StringVar(&opt.StorageClassMappingsStr, "storage-class-mappings", "", "Mapping of old to new storage classes (e.g., 'old1=new1,old2=new2')")
	cmd.Flags().BoolVar(&opt.RestorePVs, "restore-pvs", false, "Specify whether to restore PersistentVolumes")

	return cmd
}

func (opt *options) performRestore() error {
	if dumpImplementer == nil {
		return fmt.Errorf("dumpImplementer is nil")
	}
	if err := dumpImplementer.RestoreManifests(context.Background()); err != nil {
		return fmt.Errorf("failed to restore manifests: %w", err)
	}
	return nil
}

func (opt *options) setupDumpImplementer() error {
	var err error
	dumpImplementer, err = dump.NewResourceManager(opt.Options)
	return err
}

func (opt *options) prepareDirectories() (err error) {
	if err = os.MkdirAll(ScratchDir, 0o755); err != nil {
		return err
	}
	if opt.DataDir == "" {
		opt.DataDir = DestinationDir
	}
	if err := os.MkdirAll(opt.DataDir, 0o755); err != nil {
		return fmt.Errorf("failed to create data dir: %w", err)
	}
	if opt.DryRunDir != "" {
		opt.DryRunDir = filepath.Join(opt.DryRunDir, "DryRun")
		if err := os.MkdirAll(opt.DryRunDir, 0o755); err != nil {
			return fmt.Errorf("error while creating dry run directory: %w", err)
		}
	}
	return nil
}

func (opt *options) runRestoreViaPod(pod *core.Pod, snapshotName string) error {
	if err := opt.runCmdViaPod(pod, snapshotName); err != nil {
		return err
	}

	if err := opt.copyDownloadedDataToDestination(pod); err != nil {
		return err
	}

	if err := opt.clearDataFromPod(pod); err != nil {
		return err
	}

	klog.Infof("Snapshot %s/%s restored in path %s", srcNamespace, snapshotName, opt.DataDir)
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

func (opt *options) copyDownloadedDataToDestination(pod *core.Pod) error {
	_, err := exec.Command(CmdKubectl, "cp", fmt.Sprintf("%s/%s:%s", pod.Namespace, pod.Name, SnapshotDownloadDir), opt.DataDir).CombinedOutput()
	if err != nil {
		return err
	}
	return nil
}

func (opt *options) clearDataFromPod(pod *core.Pod) error {
	cmd := []string{"rm", "-rf", SnapshotDownloadDir}
	_, err := execOnPod(opt.Config, pod, cmd)
	return err
}

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
