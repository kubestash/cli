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
	"k8s.io/cli-runtime/pkg/genericclioptions"
	kmapi "kmodules.xyz/client-go/api/v1"
	"kubestash.dev/apimachinery/apis"
	"kubestash.dev/cli/pkg/common"
	"kubestash.dev/cli/pkg/common/dump"
	"path/filepath"

	"github.com/spf13/cobra"
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

func NewCmdRestore(clientGetter genericclioptions.RESTClientGetter) *cobra.Command {
	cmd := &cobra.Command{
		Use:               "restore",
		Short:             "Restore Kubernetes resources",
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			//flags.EnsureRequiredFlags(cmd, "restoresession")
			var err error
			opt.Config, err = clientGetter.ToRESTConfig()
			if err != nil {
				return err
			}

			opt.Client, err = common.NewRuntimeClient(opt.Config)
			if err != nil {
				return fmt.Errorf("failed to get kubernetes client: %w", err)
			}

			/*
				opt.RestoreSession, err = opt.GetRestoreSession()
				if err != nil {
					return fmt.Errorf("failed to get restoresession %s/%s: %w", opt.Namespace, opt.RestoreSessionName, err)
				}
			*/

			opt.Snapshot, err = opt.GetSnapshot(kmapi.ObjectReference{
				Name:      opt.SnapshotName,
				Namespace: "demo",
			})
			if err != nil {
				return fmt.Errorf("failed to get snapshot %s/%s: %w", "demo", opt.SnapshotName, err)
			}

			opt.DataDir = filepath.Join(opt.SetupOptions.ScratchDir, apis.ComponentManifest)
			if err = common.ClearDir(opt.DataDir); err != nil {
				return fmt.Errorf("failed to cleanup data dir %s: %w", opt.DataDir, err)
			}

			fmt.Println("####Checking the directory %s...\n", opt.DataDir)

			/*
				if err := opt.InitRestoreComponentStatus(); err != nil {
					return fmt.Errorf("failed to update restoresession status :%w", err)
				}
			*/
			if err := opt.setupDumpImplementer(); err != nil {
				return fmt.Errorf("failed to setup dump implementer: %w", err)
			}

			if err = opt.performRestore(); err != nil {
				opt.UpsertRestoreComponentStatus(nil, err)
			}
			/*
				if err := opt.UpdateRestoreSessionStatus(); err != nil {
					return fmt.Errorf("failed to update restoresession status: %w", err)
				}
			*/
			return nil
		},
	}

	cmd.Flags().StringVar(&masterURL, "master", masterURL, "The address of the Kubernetes API server (overrides any value in kubeconfig)")
	cmd.Flags().StringVar(&kubeconfigPath, "kubeconfig", kubeconfigPath, "Path to kubeconfig file with authorization information (the master location is set by the master flag)")

	cmd.Flags().StringVar(&opt.RestoreSessionName, "restoresession", opt.RestoreSessionName, "Name of the RestoreSession")
	cmd.Flags().StringVar(&opt.Namespace, "namespace", "default", "Namespace of the RestoreSession")
	cmd.Flags().StringVar(&opt.TargetNamespace, "target-namespace", "default", "Namespace where the resources will be restored")
	cmd.Flags().StringVar(&opt.SnapshotName, "snapshot", "", "Name of the snapshot")

	cmd.Flags().StringVar(&opt.SetupOptions.ScratchDir, "scratch-dir", opt.SetupOptions.ScratchDir, "Temporary directory")
	cmd.Flags().BoolVar(&opt.SetupOptions.EnableCache, "enable-cache", opt.SetupOptions.EnableCache, "Specify whether to enable caching for restic")

	cmd.Flags().StringSliceVar(&opt.IncludeNamespaces, "include-namespaces", opt.IncludeNamespaces, "Namespaces to include in restore (comma-separated, e.g., 'default,kube-system')")
	cmd.Flags().StringSliceVar(&opt.ExcludeNamespaces, "exclude-namespaces", opt.ExcludeNamespaces, "Namespaces to exclude from restore (comma-separated, e.g., 'kube-public,temp')")
	cmd.Flags().StringSliceVar(&opt.IncludeResources, "include-resources", opt.IncludeResources, "Resource types to include (comma-separated, e.g., 'pods,deployments')")
	cmd.Flags().StringSliceVar(&opt.ExcludeResources, "exclude-resources", opt.ExcludeResources, "Resource types to exclude (comma-separated, e.g., 'secrets,configmaps')")
	cmd.Flags().StringSliceVar(&opt.ANDedLabelSelector, "and-label-selectors", opt.ANDedLabelSelector, "A set of labels, all of which need to be matched to filter the resources.")
	cmd.Flags().StringSliceVar(&opt.ORedLabelSelector, "or-label-selectors", opt.ORedLabelSelector, "A set of labels, a subset of which need to be matched to filter the resources.")

	cmd.Flags().BoolVar(&opt.IncludeClusterResources, "include-cluster-resources", false, "Specify whether to restore cluster scoped resources")
	cmd.Flags().BoolVar(&opt.OverrideResources, "override-resources", false, "Specify whether to override resources while restoring")

	cmd.Flags().StringVar(&opt.StorageClassMappingsStr, "storage-class-mappings", "", "Mapping of old to new storage classes (e.g., 'old1=new1,old2=new2')")
	cmd.Flags().BoolVar(&opt.RestorePVs, "restore-pvs", false, "Specify whether to restore PersistentVolumes")

	return cmd
}

func (opt *options) performRestore() error {
	w, err := opt.GetResticWrapperForSnapshots(*opt.Snapshot)
	if err != nil {
		return fmt.Errorf("failed to initiate restic wrapper: %w", err)
	}
	opt.RestoreOptions.Snapshots, err = opt.GetResticSnapshotIDs()
	if err != nil {
		return err
	}

	fmt.Println("Running restic restore...")
	_, err = w.RunRestore(opt.Snapshot.Spec.Repository, opt.RestoreOptions)
	if err != nil {
		return err
	}
	fmt.Println("Restic restore completed.")

	if dumpImplementer == nil {
		return fmt.Errorf("dumpImplementer is nil")
	}

	fmt.Println("Calling RestoreManifests...")
	if err = dumpImplementer.RestoreManifests(context.Background()); err != nil {
		return fmt.Errorf("failed to restore manifests: %w", err)
	}
	fmt.Println("RestoreManifests completed.")

	return nil
}

func (opt *options) setupDumpImplementer() error {
	var err error
	dumpImplementer, err = dump.NewResourceManager(opt.Options)
	return err
}
