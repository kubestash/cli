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
	"strings"

	"github.com/spf13/cobra"
	"gomodules.xyz/flags"
	core "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
	kmapi "kmodules.xyz/client-go/api/v1"
	v1 "kmodules.xyz/offshoot-api/api/v1"
	"kubestash.dev/apimachinery/pkg/restic"
)

func NewCmdRemoveKey(opt *keyOptions) *cobra.Command {
	var idPaths []string
	cmd := &cobra.Command{
		Use:               "remove",
		Short:             `Remove keys (passwords) from restic repositories`,
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags.EnsureRequiredFlags(cmd, "id-paths")

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

			for _, idPath := range idPaths {
				idWithPath, err := parseIdPaths(idPath)
				if err != nil {
					return err
				}

				opt.ID = idWithPath[0]
				opt.paths = idWithPath[1:]

				if backupStorage.Spec.Storage.Local != nil {
					if !backupStorage.LocalNetworkVolume() {
						return fmt.Errorf("unsupported type of local backend provided")
					}

					accessorPod, err := getLocalBackendAccessorPod(opt.repo.Spec.StorageRef)
					if err != nil {
						return err
					}

					if err = opt.removeResticKeyViaPod(accessorPod); err != nil {
						return err
					}
					continue
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
					if err = opt.removeResticKeyViaPod(&operatorPod); err != nil {
						return err
					}
					continue
				}

				if err = opt.removeResticKeyViaDocker(); err != nil {
					return err
				}
			}
			return nil
		},
	}

	cmd.Flags().StringSliceVar(&idPaths, "id-paths", idPaths, "List of restic password ID and corresponding component path (restic repository) pairs. The specified passwords, associated with the given IDs, will be removed from the restic repositories.")

	return cmd
}

func (opt *keyOptions) removeResticKeyViaPod(pod *core.Pod) error {
	if err := opt.runCmdViaPod("remove-key", pod); err != nil {
		return err
	}

	klog.Infof("Restic key has been removed successfully for repository %s/%s", opt.repo.Namespace, opt.repo.Name)
	return nil
}

func (opt *keyOptions) removeResticKeyViaDocker() error {
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

	setupOptions := restic.SetupOptions{
		Client:           klient,
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

	for _, path := range opt.paths {
		setupOptions.Directory = filepath.Join(opt.repo.Spec.Path, path)

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

func parseIdPaths(idPath string) ([]string, error) {
	s := strings.Split(idPath, ":")
	if len(s) != 2 {
		return nil, fmt.Errorf("invalid format is provided for id and paths")
	}
	return s, nil
}
