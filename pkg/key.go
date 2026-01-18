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
	storageapi "kubestash.dev/apimachinery/apis/storage/v1alpha1"
	"kubestash.dev/apimachinery/pkg"
	"kubestash.dev/apimachinery/pkg/restic"
)

type keyOptions struct {
	restic.KeyOptions
	config *rest.Config
	repo   *storageapi.Repository
	paths  []string
}

func NewCmdKey(clientGetter genericclioptions.RESTClientGetter) *cobra.Command {
	opt := &keyOptions{}
	cmd := &cobra.Command{
		Use:               "password",
		Aliases:           []string{"pw"},
		Short:             `Manage restic keys (passwords) for accessing the repository`,
		DisableAutoGenTag: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			var err error
			opt.config, err = clientGetter.ToRESTConfig()
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

			return nil
		},
	}

	cmd.AddCommand(NewCmdAddKey(opt))
	cmd.AddCommand(NewCmdListKey(opt))
	cmd.AddCommand(NewCmdRemoveKey(opt))
	cmd.AddCommand(NewCmdUpdateKey(opt))

	return cmd
}

func (opt *keyOptions) copyPasswordFileToPod(pod *core.Pod) error {
	_, err := exec.Command(CmdKubectl, "cp", opt.File, fmt.Sprintf("%s/%s:%s", pod.Namespace, pod.Name, PasswordFile)).CombinedOutput()
	if err != nil {
		return err
	}
	return nil
}

func (opt *keyOptions) removePasswordFileFromPod(pod *core.Pod) error {
	cmd := []string{"rm", "-rf", PasswordFile}
	_, err := execOnPod(opt.config, pod, cmd)
	return err
}

func (opt *keyOptions) runCmdViaPod(cmd string, pod *core.Pod) error {
	command := []string{
		"/kubestash",
		cmd, opt.repo.Name,
		"--namespace", opt.repo.Namespace,
	}

	if len(opt.paths) > 1 {
		command = append(command, "--paths", strings.Join(opt.paths, ","))
	}

	if opt.ID != "" {
		command = append(command, "--path", opt.paths[0])
		command = append(command, "--id", opt.ID)
	}

	if opt.File != "" {
		command = append(command, "--new-password-file", PasswordFile)
	}

	if opt.User != "" {
		command = append(command, "--user", opt.User)
	}

	if opt.Host != "" {
		command = append(command, "--host=", opt.Host)
	}

	out, err := execOnPod(opt.config, pod, command)
	if err != nil {
		return err
	}
	klog.Infoln("Output:\n", out)
	return nil
}

func (opt *keyOptions) runCmdViaDocker(args []string) error {
	// get current user
	currentUser, err := user.Current()
	if err != nil {
		return err
	}

	keyArgs := []string{
		"run",
		"--rm",
		"-u", currentUser.Uid,
		"-v", ScratchDir + ":" + ScratchDir,
		"--env", fmt.Sprintf("%s=", EnvHttpProxy) + os.Getenv(EnvHttpProxy),
		"--env", fmt.Sprintf("%s=", EnvHttpsProxy) + os.Getenv(EnvHttpsProxy),
		"--env-file", filepath.Join(ConfigDir, ResticEnvs),
	}

	if opt.File != "" {
		keyArgs = append(keyArgs, "-v", opt.File+":"+opt.File)
	}

	keyArgs = append(keyArgs, imgRestic.Image)
	keyArgs = append(keyArgs, args...)

	if opt.ID != "" {
		keyArgs = append(keyArgs, opt.ID)
	}

	if opt.File != "" {
		keyArgs = append(keyArgs, "--new-password-file", opt.File)
	}

	if opt.User != "" {
		keyArgs = append(keyArgs, "--user", opt.User)
	}

	if opt.Host != "" {
		keyArgs = append(keyArgs, "--host", opt.Host)
	}

	klog.Infoln("Running docker with args:", keyArgs)

	out, err := exec.Command(CmdDocker, keyArgs...).CombinedOutput()
	if err != nil {
		return err
	}
	klog.Infoln("Output:\n", string(out))
	return nil
}
