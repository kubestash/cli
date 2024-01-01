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
	"strings"

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
)

type unlockOptions struct {
	restConfig *rest.Config
	repo       *storageapi.Repository
	paths      []string
}

func NewCmdUnlockRepository(clientGetter genericclioptions.RESTClientGetter) *cobra.Command {
	unlockOpt := unlockOptions{}
	cmd := &cobra.Command{
		Use:               "unlock",
		Short:             `Unlock Restic Repositories`,
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			repoName := args[0]

			var err error
			unlockOpt.restConfig, err = clientGetter.ToRESTConfig()
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

			unlockOpt.repo, err = getRepository(kmapi.ObjectReference{
				Name:      repoName,
				Namespace: srcNamespace,
			})
			if err != nil {
				return err
			}

			backupStorage, err := getBackupStorage(kmapi.ObjectReference{
				Name:      unlockOpt.repo.Spec.StorageRef.Name,
				Namespace: unlockOpt.repo.Spec.StorageRef.Namespace,
			})
			if err != nil {
				return err
			}

			if len(unlockOpt.paths) == 0 {
				unlockOpt.paths = unlockOpt.repo.Status.ComponentPaths
			}

			if backupStorage.Spec.Storage.Local != nil {
				if !backupStorage.LocalNetworkVolume() {
					return fmt.Errorf("unsupported type of local backend provided")
				}

				accessorPod, err := getLocalBackendAccessorPod(unlockOpt.repo.Spec.StorageRef)
				if err != nil {
					return err
				}

				return unlockOpt.unlockRepositoryViaPod(accessorPod)
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
				return unlockOpt.unlockRepositoryViaPod(&operatorPod)
			}

			return unlockOpt.unlockRepositoryViaDocker()
		},
	}

	cmd.Flags().StringSliceVar(&unlockOpt.paths, "paths", unlockOpt.paths, "List of component paths to unlock the corresponding restic repositories")

	return cmd
}

func (opt *unlockOptions) unlockRepositoryViaPod(pod *core.Pod) error {
	command := []string{
		"/kubestash",
		"unlock", opt.repo.Name,
		"--namespace", opt.repo.Namespace,
		"--paths", strings.Join(opt.paths, ","),
	}

	out, err := execOnPod(opt.restConfig, pod, command)
	if err != nil {
		return err
	}
	klog.Infoln("Output:", out)

	return nil
}

func (opt *unlockOptions) unlockRepositoryViaDocker() error {
	setupOptions := restic.SetupOptions{
		Client:           klient,
		BackupStorage:    &opt.repo.Spec.StorageRef,
		EncryptionSecret: opt.repo.Spec.EncryptionSecret,
	}

	// apply nice, ionice settings from env
	var err error
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

		unlockArgs := []string{
			"unlock",
			"--no-cache",
		}

		// For TLS secured Minio/REST server, specify cert path
		if w.GetCaPath() != "" {
			unlockArgs = append(unlockArgs, "--cacert", w.GetCaPath())
		}

		// run unlock inside docker
		if err = opt.runCmdViaDocker(unlockArgs); err != nil {
			return err
		}

		klog.Infof("Path: %s of Repository %s/%s has been unlocked successfully", path, opt.repo.Namespace, opt.repo.Name)
	}

	return nil
}

func (opt *unlockOptions) runCmdViaDocker(args []string) error {
	// get current user
	currentUser, err := user.Current()
	if err != nil {
		return err
	}

	unlockArgs := []string{
		"run",
		"--rm",
		"-u", currentUser.Uid,
		"-v", ScratchDir + ":" + ScratchDir,
		"--env", fmt.Sprintf("%s=", EnvHttpProxy) + os.Getenv(EnvHttpProxy),
		"--env", fmt.Sprintf("%s=", EnvHttpsProxy) + os.Getenv(EnvHttpsProxy),
		"--env-file", filepath.Join(ConfigDir, ResticEnvs),
		imgRestic.ToContainerImage(),
	}

	unlockArgs = append(unlockArgs, args...)
	klog.Infoln("Running docker with args:", unlockArgs)
	out, err := exec.Command(CmdDocker, unlockArgs...).CombinedOutput()
	klog.Infoln("Output:", string(out))
	return err
}
