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

type unlockOptions struct {
	repo      *storageapi.Repository
	configDir string
	extraArgs []string
	paths     []string
}

func NewCmdUnlockRepository(clientGetter genericclioptions.RESTClientGetter) *cobra.Command {
	unlockOpt := unlockOptions{}
	cmd := &cobra.Command{
		Use:               "unlock",
		Short:             `Unlock Restic Repository`,
		Long:              `Unlock Restic Repository`,
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			repoName := args[0]

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

			// get repository
			unlockOpt.repo = &storageapi.Repository{
				ObjectMeta: metav1.ObjectMeta{
					Name:      repoName,
					Namespace: srcNamespace,
				},
			}
			if err = klient.Get(context.Background(), client.ObjectKeyFromObject(unlockOpt.repo), unlockOpt.repo); err != nil {
				return err
			}

			// get backupStorage
			backupStorage := &storageapi.BackupStorage{
				ObjectMeta: metav1.ObjectMeta{
					Name:      unlockOpt.repo.Spec.StorageRef.Name,
					Namespace: unlockOpt.repo.Spec.StorageRef.Namespace,
				},
			}
			if err = klient.Get(context.Background(), client.ObjectKeyFromObject(backupStorage), backupStorage); err != nil {
				return err
			}

			if backupStorage.Spec.Storage.Local != nil {
				return unlockOpt.unlockLocalRepository()
			}

			return unlockOpt.unlockRepository()
		},
	}

	cmd.Flags().StringSliceVar(&unlockOpt.paths, "paths", unlockOpt.paths, "List of paths for restic repository to unlock")

	err := cmd.MarkFlagRequired("paths")
	if err != nil {
		return nil
	}

	return cmd
}

func (opt *unlockOptions) unlockLocalRepository() error {
	// TODO: will be added later
	return nil
}

func (opt *unlockOptions) unlockRepository() error {
	for _, path := range opt.paths {
		setupOptions := restic.SetupOptions{
			Client:           klient,
			Directory:        filepath.Join(opt.repo.Spec.Path, path),
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

		w, err := restic.NewResticWrapper(setupOptions)
		if err != nil {
			return err
		}

		opt.configDir = filepath.Join(ScratchDir, configDirName)
		// dump restic's environments into `restic-env` file.
		// we will pass this env file to restic docker container.
		err = w.DumpEnv(opt.configDir, ResticEnvs)
		if err != nil {
			return err
		}

		opt.extraArgs = []string{
			"--no-cache",
		}

		// For TLS secured Minio/REST server, specify cert path
		if w.GetCaPath() != "" {
			opt.extraArgs = append(opt.extraArgs, "--cacert", w.GetCaPath())
		}

		// run unlock inside docker
		if err = opt.runCmdViaDocker(); err != nil {
			return err
		}

		klog.Infof("Path: %s of Repository %s/%s has been unlocked successfully", path, opt.repo.Namespace, opt.repo.Name)
	}

	return nil
}

func (opt *unlockOptions) runCmdViaDocker() error {
	// get current user
	currentUser, err := user.Current()
	if err != nil {
		return err
	}

	args := []string{
		"run",
		"--rm",
		"-u", currentUser.Uid,
		"-v", ScratchDir + ":" + ScratchDir,
		"--env", "HTTP_PROXY=" + os.Getenv("HTTP_PROXY"),
		"--env", "HTTPS_PROXY=" + os.Getenv("HTTPS_PROXY"),
		"--env-file", filepath.Join(opt.configDir, ResticEnvs),
		imgRestic.ToContainerImage(),
		"unlock",
	}

	args = append(args, opt.extraArgs...)
	klog.Infoln("Running docker with args:", args)
	out, err := exec.Command("docker", args...).CombinedOutput()
	if out == nil {
		return fmt.Errorf("lock not stale")
	}
	klog.Infoln("Output:", string(out))
	return err
}
