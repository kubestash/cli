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
	kmapi "kmodules.xyz/client-go/api/v1"
	v1 "kmodules.xyz/offshoot-api/api/v1"
	storageapi "kubestash.dev/apimachinery/apis/storage/v1alpha1"
	"kubestash.dev/apimachinery/pkg/restic"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func NewCmdDownload(clientGetter genericclioptions.RESTClientGetter) *cobra.Command {
	localDirs := &cliLocalDirectories{}
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

			snapshot := &storageapi.Snapshot{
				ObjectMeta: metav1.ObjectMeta{
					Name:      snapshotName,
					Namespace: srcNamespace,
				},
			}
			if err = klient.Get(context.Background(), client.ObjectKeyFromObject(snapshot), snapshot); err != nil {
				return err
			}

			repository := &storageapi.Repository{
				ObjectMeta: metav1.ObjectMeta{
					Name:      snapshot.Spec.Repository,
					Namespace: srcNamespace,
				},
			}
			if err = klient.Get(context.Background(), client.ObjectKeyFromObject(repository), repository); err != nil {
				return err
			}

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

			if err = localDirs.prepareDownloadDir(); err != nil {
				return err
			}

			if err = os.MkdirAll(ScratchDir, 0o755); err != nil {
				return err
			}
			defer os.RemoveAll(ScratchDir)

			for name, comp := range snapshot.Status.Components {

				localDirs.componentDir = name
				setupOptions := restic.SetupOptions{
					Client:    klient,
					Directory: filepath.Join(repository.Spec.Path, comp.Path),
					BackupStorage: &kmapi.TypedObjectReference{
						APIGroup:  backupStorage.GroupVersionKind().Group,
						Kind:      backupStorage.Kind,
						Name:      backupStorage.Name,
						Namespace: backupStorage.Namespace,
					},
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

				localDirs.configDir = filepath.Join(ScratchDir, configDirName)
				// dump restic's environments into `restic-env` file.
				// we will pass this env file to restic docker container.
				err = w.DumpEnv(localDirs.configDir, ResticEnvs)
				if err != nil {
					return err
				}

				extraArgs := []string{
					"--no-cache",
				}

				// For TLS secured Minio/REST server, specify cert path
				if w.GetCaPath() != "" {
					extraArgs = append(extraArgs, "--cacert", w.GetCaPath())
				}

				var resticSnapshots []string
				for _, resticStat := range comp.ResticStats {
					resticSnapshots = append(resticSnapshots, resticStat.Id)
				}

				// run restore inside docker
				if err = runRestoreViaDocker(*localDirs, extraArgs, resticSnapshots); err != nil {
					return err
				}
				klog.Infof("Snapshots: %v of Repository %s/%s restored in path %s", resticSnapshots, srcNamespace, repository.Name, localDirs.downloadDir)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&localDirs.downloadDir, "destination", localDirs.downloadDir, "Destination path where components will be restored.")

	return cmd
}

func runRestoreViaDocker(localDirs cliLocalDirectories, extraArgs []string, snapshots []string) error {
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
		"-v", localDirs.downloadDir + ":" + DestinationDir,
		"--env", "HTTP_PROXY=" + os.Getenv("HTTP_PROXY"),
		"--env", "HTTPS_PROXY=" + os.Getenv("HTTPS_PROXY"),
		"--env-file", filepath.Join(localDirs.configDir, ResticEnvs),
		imgRestic.ToContainerImage(),
	}

	restoreArgs = append(restoreArgs, extraArgs...)
	restoreArgs = append(restoreArgs, "restore")
	for _, snapshot := range snapshots {
		args := append(restoreArgs, snapshot, "--target", filepath.Join(DestinationDir, localDirs.componentDir))
		klog.Infoln("Running docker with args:", args)
		out, err := exec.Command("docker", args...).CombinedOutput()
		if err != nil {
			return err
		}
		klog.Infoln("Output:", string(out))
	}
	return nil
}
