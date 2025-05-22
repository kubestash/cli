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
	"path/filepath"

	"kubestash.dev/apimachinery/apis"
	"kubestash.dev/kubedump/pkg/common"
	"kubestash.dev/kubedump/pkg/common/dump"

	"github.com/spf13/cobra"
	"gomodules.xyz/flags"
	"k8s.io/client-go/tools/clientcmd"
)

type options struct {
	*common.Options
}

var (
	masterURL      string
	kubeconfigPath string
	opt            = options{
		Options: common.NewOptions(),
	}
	dumpImplementer *dump.ResourceManager
)

func NewCmdBackup() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "backup",
		Short:             "Takes backup of Kubernetes resources",
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags.EnsureRequiredFlags(cmd, "backupsession")
			var err error
			opt.Config, err = clientcmd.BuildConfigFromFlags(masterURL, kubeconfigPath)
			if err != nil {
				return err
			}

			opt.Client, err = common.NewRuntimeClient(opt.Config)
			if err != nil {
				return fmt.Errorf("failed to get kubernetes client: %w", err)
			}

			opt.BackupSession, err = opt.GetBackupSession()
			if err != nil {
				return fmt.Errorf("failed to get backupsession %s/%s: %w", opt.Namespace, opt.BackupSessionName, err)
			}

			opt.BackupConfiguration, err = opt.GetBackupConfiguration()
			if err != nil {
				return fmt.Errorf("failed to get backupconfiguration %s/%s: %w", opt.Namespace, opt.BackupSession.Spec.Invoker.Name, err)
			}

			opt.Snapshots, err = opt.GetSnapshots()
			if err != nil {
				return err
			}

			opt.DataDir = filepath.Join(opt.SetupOptions.ScratchDir, apis.ComponentManifest)
			if err = common.ClearDir(opt.DataDir); err != nil {
				return fmt.Errorf("failed to cleanup data dir %s: %w", opt.DataDir, err)
			}

			if err = opt.InitSnapshotComponentStatus(); err != nil {
				return err
			}
			if err = opt.setupDumpImplementer(); err != nil {
				return err
			}

			if err = dumpImplementer.DumpManifests(context.Background()); err != nil {
				common.UpsertSnapshotsComponentStatus(opt.Snapshots, nil, nil, err)
			} else {
				opt.performBackup()
			}

			for _, snap := range opt.Snapshots {
				if err := opt.UpdateSnapshotStatus(&snap); err != nil {
					return fmt.Errorf("failed to update snapshot status: %w", err)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&masterURL, "master", masterURL, "The address of the Kubernetes API server (overrides any value in kubeconfig)")
	cmd.Flags().StringVar(&kubeconfigPath, "kubeconfig", kubeconfigPath, "Path to kubeconfig file with authorization information (the master location is set by the master flag)")

	cmd.Flags().StringVar(&opt.Namespace, "namespace", "default", "Namespace of BackupSession")
	cmd.Flags().StringVar(&opt.BackupSessionName, "backupsession", opt.BackupSessionName, "Name of the BackupSession")

	cmd.Flags().StringVar(&opt.SetupOptions.ScratchDir, "scratch-dir", opt.SetupOptions.ScratchDir, "Temporary directory")
	cmd.Flags().BoolVar(&opt.SetupOptions.EnableCache, "enable-cache", opt.SetupOptions.EnableCache, "Specify whether to enable caching for restic")

	cmd.Flags().StringSliceVar(&opt.ANDedLabelSelector, "and-label-selectors", opt.ANDedLabelSelector, "A set of labels, all of which need to be matched to filter the resources.")
	cmd.Flags().StringSliceVar(&opt.ORedLabelSelector, "or-label-selectors", opt.ORedLabelSelector, "A set of labels, a subset of which need to be matched to filter the resources.")

	cmd.Flags().BoolVar(&opt.Sanitize, "sanitize", false, "Specify whether to remove the decorators from the resource YAML (default is false)")
	cmd.Flags().StringSliceVar(&opt.IncludeNamespaces, "include-namespaces", opt.IncludeNamespaces, "Namespaces to include in backup (comma-separated, e.g., 'default,kube-system')")
	cmd.Flags().StringSliceVar(&opt.ExcludeNamespaces, "exclude-namespaces", opt.ExcludeNamespaces, "Namespaces to exclude from backup (comma-separated, e.g., 'kube-public,temp')")
	cmd.Flags().StringSliceVar(&opt.IncludeResources, "include-resources", opt.IncludeResources, "Resource types to include (comma-separated, e.g., 'pods,deployments')")
	cmd.Flags().StringSliceVar(&opt.ExcludeResources, "exclude-resources", opt.ExcludeResources, "Resource types to exclude (comma-separated, e.g., 'secrets,configmaps')")
	cmd.Flags().BoolVar(&opt.IncludeClusterResources, "include-cluster-resources", true, "Specify whether to backup cluster scoped resources")
	return cmd
}

func (opt *options) performBackup() {
	opt.BackupOptions.BackupPaths = []string{opt.DataDir}
	w, err := opt.GetResticWrapperForSnapshots(opt.Snapshots...)
	if err != nil {
		common.UpsertSnapshotsComponentStatus(opt.Snapshots, nil, nil,
			fmt.Errorf("failed to initiate restic wrapper: %w", err))
		return
	}
	opt.InitializeRepositories(w)

	if len(w.Config.Backends) != 0 {
		backupOutput, err := w.RunBackup(opt.BackupOptions)
		opt.SetBackupOutput(w, backupOutput, err)
	}
}

func (opt *options) setupDumpImplementer() error {
	var err error
	dumpImplementer, err = dump.NewResourceManager(opt.Options)
	return err
}
