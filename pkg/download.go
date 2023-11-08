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
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	core "k8s.io/api/core/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	kmapi "kmodules.xyz/client-go/api/v1"
	v1 "kmodules.xyz/offshoot-api/api/v1"
	storageapi "kubestash.dev/apimachinery/apis/storage/v1alpha1"
	"kubestash.dev/apimachinery/pkg/restic"
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
				return fmt.Errorf("failed to read kubeconfig. Reason: %w", err)
			}

			srcNamespace, _, err = clientGetter.ToRawKubeConfigLoader().Namespace()
			if err != nil {
				return err
			}

			klient, err = newRuntimeClient(downloadOpt.restConfig)
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

			if backupStorage.Spec.Storage.Local != nil {
				if !backupStorage.LocalNetworkVolume() {
					return fmt.Errorf("local backend of type: %s not supported", backupStorage.Spec.Storage.Local.String())
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
				return downloadOpt.runRestoreViaPod(&operatorPod, snapshotName)
			}

			if err = os.MkdirAll(ScratchDir, 0o755); err != nil {
				return err
			}
			defer func() {
				err := os.RemoveAll(ScratchDir)
				if err != nil {
					klog.Errorf("failed to remove scratch dir. Reason: %w", err)
				}
			}()

			setupOptions := restic.SetupOptions{
				Client:           klient,
				BackupStorage:    &repository.Spec.StorageRef,
				EncryptionSecret: repository.Spec.EncryptionSecret,
				ScratchDir:       ScratchDir,
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
				if !downloadOpt.shouldRestoreComponent(compName) {
					continue
				}

				setupOptions.Directory = filepath.Join(repository.Spec.Path, comp.Path)

				w, err := restic.NewResticWrapper(setupOptions)
				if err != nil {
					return err
				}

				// dump restic's environments into `restic-env` file.
				// we will pass this env file to restic docker container.
				err = w.DumpEnv(ConfigDir, ResticEnvs)
				if err != nil {
					return err
				}

				restoreArgs := []string{
					"restore",
					"--cache-dir",
					ScratchDir,
				}

				// For TLS secured Minio/REST server, specify cert path
				if w.GetCaPath() != "" {
					restoreArgs = append(restoreArgs, "--cacert", w.GetCaPath())
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

	cmd.Flags().StringVar(&imgRestic.Registry, "docker-registry", imgRestic.Registry, "Docker image registry for restic cli")
	cmd.Flags().StringVar(&imgRestic.Tag, "image-tag", imgRestic.Tag, "Restic docker image tag")

	cmd.MarkFlagsMutuallyExclusive("exclude", "include")

	return cmd
}

func (opt *downloadOptions) runRestoreViaPod(pod *core.Pod, snapshotName string) error {
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
	klog.Infoln("Output:", out)
	return nil
}

func (opt *downloadOptions) copyDownloadedDataToDestination(pod *core.Pod) error {
	_, err := exec.Command(CmdKubectl, "cp", fmt.Sprintf("%s/%s:%s", pod.Namespace, pod.Name, SnapshotDownloadDir), opt.destinationDir).CombinedOutput()
	if err != nil {
		return err
	}
	return nil
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
		"--env", "HTTP_PROXY=" + os.Getenv("HTTP_PROXY"),
		"--env", "HTTPS_PROXY=" + os.Getenv("HTTPS_PROXY"),
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

func (opt *downloadOptions) shouldRestoreComponent(componentName string) bool {
	if opt.components == nil {
		return true
	}

	for _, comp := range opt.components {
		if comp == componentName {
			return true
		}
	}
	return false
}
