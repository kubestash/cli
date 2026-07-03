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
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"gomodules.xyz/restic"
	core "k8s.io/api/core/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	kmapi "kmodules.xyz/client-go/api/v1"
	v1 "kmodules.xyz/offshoot-api/api/v1"
	storageapi "kubestash.dev/apimachinery/apis/storage/v1alpha1"
	"kubestash.dev/apimachinery/pkg"
	"kubestash.dev/apimachinery/pkg/resolver"
)

type downloadOptions struct {
	restConfig     *rest.Config
	destinationDir string // user provided or, current working dir

	resticStats []storageapi.ResticStats
	components  []string
	exclude     []string
	include     []string
}

func NewCmdDownload(clientGetter genericclioptions.RESTClientGetter) *cobra.Command {
	downloadOpt := &downloadOptions{}
	cmd := &cobra.Command{
		Use:               "download",
		Short:             `Download components of a snapshot`,
		Long:              `Download components of a snapshot from restic repositories`,
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			snapshotName := args[0]

			var err error
			downloadOpt.restConfig, err = clientGetter.ToRESTConfig()
			if err != nil {
				return fmt.Errorf("failed to read kubeconfig. Reason: %v", err)
			}

			srcNamespace, _, err = clientGetter.ToRawKubeConfigLoader().Namespace()
			if err != nil {
				return err
			}

			klient, err = pkg.NewUncachedClient(clientGetter)
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

			if err = downloadOpt.prepareDestinationDir(); err != nil {
				return err
			}

			klog.Infof("Resolved Snapshot %s/%s -> Repository %s -> BackupStorage %s/%s (provider: %s)",
				srcNamespace, snapshotName, repository.Name,
				backupStorage.Namespace, backupStorage.Name, backupStorage.Spec.Storage.Provider)

			if backupStorage.Spec.Storage.Local != nil {
				switch {
				case backupStorage.LocalNetworkVolume():
					klog.Infof("Local backend type: NFS (server: %s)", backupStorage.Spec.Storage.Local.NFS.Server)
				case backupStorage.LocalBackendPVC():
					klog.Infof("Local backend type: PersistentVolumeClaim (claim: %s, mountPath: %s)",
						backupStorage.Spec.Storage.Local.PersistentVolumeClaim.ClaimName, backupStorage.Spec.Storage.Local.MountPath)
				default:
					return fmt.Errorf("unsupported type of local backend provided: BackupStorage %s/%s uses a local volume source that is neither NFS nor PersistentVolumeClaim",
						backupStorage.Namespace, backupStorage.Name)
				}

				accessorPod, err := getLocalBackendAccessorPod(repository.Spec.StorageRef)
				if err != nil {
					return err
				}

				return downloadOpt.runRestoreViaPod(accessorPod, snapshotName)
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
				klog.Infof("Workload identity detected on operator pod %s/%s; downloading via operator pod", operatorPod.Namespace, operatorPod.Name)
				return downloadOpt.runRestoreViaPod(&operatorPod, snapshotName)
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

			encryptSecret, err := getEncryptionSecret(klient, repository.Spec.EncryptionSecret)
			if err != nil {
				return fmt.Errorf("failed to get encryption secret. Reason: %w", err)
			}

			setupOptions := &restic.SetupOptions{
				ScratchDir: ScratchDir,
				Backends: []*restic.Backend{
					{
						ConfigResolver:   resolver.NewBackupStorageResolver(klient, backupStorage),
						Repository:       repository.Name,
						EncryptionSecret: encryptSecret,
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
				if len(downloadOpt.components) != 0 &&
					!slices.Contains(downloadOpt.components, compName) {
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

				downloadOpt.resticStats = comp.ResticStats

				// run restore inside docker
				if err = downloadOpt.runRestoreViaDocker(filepath.Join(DestinationDir, snapshotName, compName), restoreArgs); err != nil {
					return err
				}

				klog.Infof("Component: %v of Snapshot %s/%s restored in path %s", compName, srcNamespace, snapshotName, downloadOpt.destinationDir)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&downloadOpt.destinationDir, "destination", downloadOpt.destinationDir, "Destination path where components will be restored.")
	cmd.Flags().StringSliceVar(&downloadOpt.components, "components", downloadOpt.components, "List of components to restore")
	cmd.Flags().StringSliceVar(&downloadOpt.exclude, "exclude", downloadOpt.exclude, "List of pattern for directory/file to ignore during restore")
	cmd.Flags().StringSliceVar(&downloadOpt.include, "include", downloadOpt.include, "List of pattern for directory/file to restore")

	cmd.Flags().StringVar(&imgRestic.Image, "image", imgRestic.Image, "Restic docker image")

	cmd.MarkFlagsMutuallyExclusive("exclude", "include")

	return cmd
}

func (opt *downloadOptions) runRestoreViaPod(pod *core.Pod, snapshotName string) error {
	if err := opt.runCmdViaPod(pod, snapshotName); err != nil {
		return fmt.Errorf("failed to run download inside pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}

	if err := opt.copyDownloadedDataToDestination(pod); err != nil {
		return fmt.Errorf("failed to copy downloaded data from pod %s/%s to %s: %w", pod.Namespace, pod.Name, opt.destinationDir, err)
	}

	if err := opt.clearDataFromPod(pod); err != nil {
		return fmt.Errorf("failed to clean up temporary data from pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}

	klog.Infof("Snapshot %s/%s restored in path %s", srcNamespace, snapshotName, opt.destinationDir)
	return nil
}

func (opt *downloadOptions) runCmdViaPod(pod *core.Pod, snapshotName string) error {
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
	if out != "" {
		klog.Infoln("Output:", out)
	}
	return nil
}

func (opt *downloadOptions) copyDownloadedDataToDestination(pod *core.Pod) error {
	if strings.EqualFold(os.Getenv(EnvCopyMode), CopyModeCP) {
		cmd := exec.Command(CmdKubectl, "cp", fmt.Sprintf("%s/%s:%s", pod.Namespace, pod.Name, SnapshotDownloadDir), opt.destinationDir)
		klog.Infof("Copying downloaded data with: %v", cmd.Args)
		out, err := cmd.CombinedOutput()
		if len(out) > 0 {
			klog.Infoln("kubectl cp output:", string(out))
		}
		if err != nil {
			return fmt.Errorf("kubectl cp failed: %w, output: %q", err, string(out))
		}
		return nil
	}
	return copyDataFromPodViaTar(opt.restConfig, pod, SnapshotDownloadDir, opt.destinationDir)
}

func (opt *downloadOptions) clearDataFromPod(pod *core.Pod) error {
	cmd := []string{"rm", "-rf", SnapshotDownloadDir}
	_, err := execOnPod(opt.restConfig, pod, cmd)
	return err
}

func (opt *downloadOptions) prepareDestinationDir() (err error) {
	// if destination flag is not specified, restore in current directory
	if opt.destinationDir == "" {
		if opt.destinationDir, err = os.Getwd(); err != nil {
			return err
		}
	}
	return os.MkdirAll(opt.destinationDir, 0o755)
}

func (opt *downloadOptions) runRestoreViaDocker(destination string, args []string) error {
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
		imgRestic.Image,
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
		rargs := append(restoreArgs, resticStat.Summary.Id, "--target", destination)
		klog.Infoln("Running docker with args:", rargs)
		out, err := exec.Command(CmdDocker, rargs...).CombinedOutput()
		klog.Infoln("Output:", string(out))
		if err != nil {
			return err
		}
	}
	return nil
}
