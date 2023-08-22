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

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/klog/v2"
	v1 "kmodules.xyz/offshoot-api/api/v1"
	storageapi "kubestash.dev/apimachinery/apis/storage/v1alpha1"
	"kubestash.dev/apimachinery/pkg/restic"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type downloadOptions struct {
	configDir      string // temp dir
	destinationDir string // user provided or, current working dir

	resticStats []storageapi.ResticStats
	components  []string
	extraArgs   []string
	exclude     []string
	include     []string
}

func NewCmdDownload(clientGetter genericclioptions.RESTClientGetter) *cobra.Command {
	downloadOpt := &downloadOptions{}
	cmd := &cobra.Command{
		Use:               "download",
		Short:             `Download components`,
		Long:              `Download components of a snapshot`,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 || args[0] == "" {
				return fmt.Errorf("snapshot name not found")
			}

			snapshotName := args[0]

			cfg, err := clientGetter.ToRESTConfig()
			if err != nil {
				return errors.Wrap(err, "failed to read kubeconfig")
			}

			srcNamespace, _, err = clientGetter.ToRawKubeConfigLoader().Namespace()
			if err != nil {
				return err
			}

			klient, err = newRuntimeClient(cfg)
			if err != nil {
				return err
			}

			// get snapshot
			snapshot := &storageapi.Snapshot{
				ObjectMeta: metav1.ObjectMeta{
					Name:      snapshotName,
					Namespace: srcNamespace,
				},
			}
			if err = klient.Get(context.Background(), client.ObjectKeyFromObject(snapshot), snapshot); err != nil {
				return err
			}

			// get repository
			repository := &storageapi.Repository{
				ObjectMeta: metav1.ObjectMeta{
					Name:      snapshot.Spec.Repository,
					Namespace: srcNamespace,
				},
			}
			if err = klient.Get(context.Background(), client.ObjectKeyFromObject(repository), repository); err != nil {
				return err
			}

			// get backupStorage
			backupStorage := &storageapi.BackupStorage{
				ObjectMeta: metav1.ObjectMeta{
					Name:      repository.Spec.StorageRef.Name,
					Namespace: repository.Spec.StorageRef.Namespace,
				},
			}
			if err = klient.Get(context.Background(), client.ObjectKeyFromObject(backupStorage), backupStorage); err != nil {
				return err
			}

			if backupStorage.Spec.Storage.Local != nil {
				return fmt.Errorf("can't restore from repository with local backend")
			}

			if err = downloadOpt.prepareDestinationDir(); err != nil {
				return err
			}

			if err = os.MkdirAll(ScratchDir, 0o755); err != nil {
				return err
			}
			defer os.RemoveAll(ScratchDir)

			for compName, comp := range snapshot.Status.Components {
				if !downloadOpt.shouldRestoreComponent(compName) {
					continue
				}

				setupOptions := restic.SetupOptions{
					Client:           klient,
					Directory:        filepath.Join(repository.Spec.Path, comp.Path),
					BackupStorage:    &repository.Spec.StorageRef,
					EncryptionSecret: repository.Spec.EncryptionSecret,
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

				w, err := restic.NewResticWrapper(setupOptions)
				if err != nil {
					return err
				}

				downloadOpt.configDir = filepath.Join(ScratchDir, configDirName)
				// dump restic's environments into `restic-env` file.
				// we will pass this env file to restic docker container.
				err = w.DumpEnv(downloadOpt.configDir, ResticEnvs)
				if err != nil {
					return err
				}

				downloadOpt.extraArgs = []string{
					"--no-cache",
				}

				// For TLS secured Minio/REST server, specify cert path
				if w.GetCaPath() != "" {
					downloadOpt.extraArgs = append(downloadOpt.extraArgs, "--cacert", w.GetCaPath())
				}

				downloadOpt.resticStats = comp.ResticStats

				// run restore inside docker
				if err = downloadOpt.runRestoreViaDocker(compName); err != nil {
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

	return cmd
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

func (opt *downloadOptions) runRestoreViaDocker(componentName string) error {
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
		"--env-file", filepath.Join(opt.configDir, ResticEnvs),
		imgRestic.ToContainerImage(),
	}

	restoreArgs = append(restoreArgs, opt.extraArgs...)
	restoreArgs = append(restoreArgs, "restore")

	for _, include := range opt.include {
		restoreArgs = append(restoreArgs, "--include")
		restoreArgs = append(restoreArgs, include)
	}

	for _, exclude := range opt.exclude {
		restoreArgs = append(restoreArgs, "--exclude")
		restoreArgs = append(restoreArgs, exclude)
	}

	destinationPath := filepath.Join(DestinationDir, componentName)

	for _, resticStat := range opt.resticStats {
		args := append(restoreArgs, resticStat.Id, "--target", filepath.Join(destinationPath, resticStat.Id[:8]))
		klog.Infoln("Running docker with args:", args)
		out, err := exec.Command("docker", args...).CombinedOutput()
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
