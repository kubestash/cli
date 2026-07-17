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
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"gomodules.xyz/restic"
	core "k8s.io/api/core/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	storageapi "kubestash.dev/apimachinery/apis/storage/v1alpha1"
	"kubestash.dev/apimachinery/pkg"
)

type keyOptions struct {
	restic.KeyOptions
	config *rest.Config
	repo   *storageapi.Repository
	paths  []string

	// Alternative sources for the new password. Exactly one of
	// opt.File (--new-password-file), newPassword (--new-password) and
	// newPasswordStdin (--new-password-stdin) must be set. They are resolved
	// into opt.File by preparePasswordFile() before the rest of the flow runs.
	newPassword      string
	newPasswordStdin bool
}

// preparePasswordFile resolves the new-password source into opt.File.
//
//   - --new-password-file: opt.File is used as-is; the caller's file is left
//     intact and the returned cleanup is a no-op.
//   - --new-password / --new-password-stdin: the value (or stdin) is written to a
//     temporary file, opt.File is pointed at it, and the returned cleanup removes
//     it. The temp file is created with mode 0600 by os.CreateTemp.
//
// Exactly one source must be provided. Because both the pod path
// (copyPasswordFileToPod) and the docker path (runCmdViaDocker) only ever
// consume opt.File, materializing it here keeps every downstream path working
// unchanged.
func (opt *keyOptions) preparePasswordFile() (func(), error) {
	noop := func() {}

	sources := 0
	if opt.File != "" {
		sources++
	}
	if opt.newPassword != "" {
		sources++
	}
	if opt.newPasswordStdin {
		sources++
	}

	if sources == 0 {
		return noop, fmt.Errorf("one of --new-password-file, --new-password or --new-password-stdin is required")
	}
	if sources > 1 {
		return noop, fmt.Errorf("at most one of --new-password-file, --new-password or --new-password-stdin may be set")
	}

	// --new-password-file: use the provided file directly.
	if opt.File != "" {
		return noop, nil
	}

	// --new-password / --new-password-stdin: materialize a temp file.
	f, err := os.CreateTemp("", "kubestash-newpw-")
	if err != nil {
		return noop, fmt.Errorf("failed to create temp password file: %w", err)
	}

	var data []byte
	if opt.newPasswordStdin {
		data, err = io.ReadAll(os.Stdin)
		if err != nil {
			_ = f.Close()
			_ = os.Remove(f.Name())
			return noop, fmt.Errorf("failed to read new password from stdin: %w", err)
		}
	} else {
		data = []byte(opt.newPassword)
	}

	// Write verbatim; restic trims trailing newlines from password files, so
	// `echo 'pw' | --new-password-stdin` (data "pw\n") matches the existing
	// `echo 'pw' > file; --new-password-file` behavior.
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return noop, fmt.Errorf("failed to write temp password file: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(f.Name())
		return noop, fmt.Errorf("failed to close temp password file: %w", err)
	}

	opt.File = f.Name()
	return func() { _ = os.Remove(f.Name()) }, nil
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
