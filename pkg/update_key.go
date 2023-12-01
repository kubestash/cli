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
	"path/filepath"

	"github.com/spf13/cobra"
	core "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
	kmapi "kmodules.xyz/client-go/api/v1"
	v1 "kmodules.xyz/offshoot-api/api/v1"
	"kubestash.dev/apimachinery/pkg/restic"
)

func NewCmdUpdateKey(opt *keyOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:               "update",
		Short:             `Update current key (password) for restic repositories`,
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			repoName := args[0]

			var err error
			opt.repo, err = getRepository(kmapi.ObjectReference{
				Name:      repoName,
				Namespace: srcNamespace,
			})
			if err != nil {
				return err
			}

			backupStorage, err := getBackupStorage(kmapi.ObjectReference{
				Name:      opt.repo.Spec.StorageRef.Name,
				Namespace: opt.repo.Spec.StorageRef.Namespace,
			})
			if err != nil {
				return err
			}

			if len(opt.paths) == 0 {
				opt.paths = opt.repo.Status.ComponentPaths
			}

			if backupStorage.Spec.Storage.Local != nil {
				if !backupStorage.LocalNetworkVolume() {
					return fmt.Errorf("unsupported type of local backend provided")
				}

				accessorPod, err := getLocalBackendAccessorPod(opt.repo.Spec.StorageRef)
				if err != nil {
					return err
				}

				return opt.updateResticKeyViaPod(accessorPod)
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
				return opt.updateResticKeyViaPod(&operatorPod)
			}

			return opt.updateResticKeyViaDocker()
		},
	}

	cmd.Flags().StringVar(&opt.File, "new-password-file", opt.File, "File from which to read the new password")
	cmd.Flags().StringSliceVar(&opt.paths, "paths", opt.paths, "List of component paths (restic repositories) to update the password")

	return cmd
}

func (opt *keyOptions) updateResticKeyViaPod(pod *core.Pod) error {
	if err := opt.copyPasswordFileToPod(pod); err != nil {
		return fmt.Errorf("failed to copy password file from local directory to pod: %w", err)
	}

	if err := opt.runCmdViaPod("update-key", pod); err != nil {
		return err
	}

	if err := opt.removePasswordFileFromPod(pod); err != nil {
		return fmt.Errorf("failed to remove password file from pod: %w", err)
	}

	klog.Infof("Restic key has been updated successfully for repository %s/%s", opt.repo.Namespace, opt.repo.Name)
	return nil
}

func (opt *keyOptions) updateResticKeyViaDocker() error {
	var err error
	if err = os.MkdirAll(ScratchDir, 0o755); err != nil {
		return err
	}
	defer func() {
		err := os.RemoveAll(ScratchDir)
		if err != nil {
			klog.Errorf("failed to remove scratch dir. Reason: %w", err)
		}
	}()

	for _, path := range opt.paths {
		setupOptions := restic.SetupOptions{
			Client:           klient,
			Directory:        filepath.Join(opt.repo.Spec.Path, path),
			BackupStorage:    &opt.repo.Spec.StorageRef,
			EncryptionSecret: opt.repo.Spec.EncryptionSecret,
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

		keyArgs := []string{
			"key",
			"remove",
			opt.ID,
			"--no-cache",
		}

		// For TLS secured Minio/REST server, specify cert path
		if w.GetCaPath() != "" {
			keyArgs = append(keyArgs, "--cacert", w.GetCaPath())
		}

		if err = opt.runCmdViaDocker(keyArgs); err != nil {
			return err
		}
	}
	return nil
}
