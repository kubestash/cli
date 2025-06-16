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

package common

import (
	"kubestash.dev/apimachinery/apis"
	coreapi "kubestash.dev/apimachinery/apis/core/v1alpha1"
	storageapi "kubestash.dev/apimachinery/apis/storage/v1alpha1"
	"kubestash.dev/apimachinery/pkg/restic"
	"os"

	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type ResourceItems struct {
	GroupResource    string
	ItemsByNamespace map[string][]string
}
type RestoreableItem struct {
	Path            string
	TargetNamespace string
	Name            string
	Version         string
}

type RestoreableResource struct {
	Resource                 string
	SelectedItemsByNamespace map[string][]RestoreableItem
	TotalItems               int
}

type ItemKey struct {
	Resource  string
	Namespace string
	Name      string
}

type RestoredItemStatus struct {
	Action     string
	ItemExists bool
}

type Options struct {
	Config          *rest.Config
	Client          client.Client
	DataDir         string
	DryRunDir       string
	WaitTimeout     int32
	Namespace       string
	TargetNamespace string

	SnapshotName      string
	BackupSessionName string

	SetupOptions   restic.SetupOptions
	BackupOptions  restic.BackupOptions
	RestoreOptions restic.RestoreOptions

	ResticStats []storageapi.ResticStats
	Components  []string
	Exclude     []string
	Include     []string
	Paths       []string

	Target              *v1.TypedObjectReference
	Snapshot            *storageapi.Snapshot
	Snapshots           []storageapi.Snapshot
	BackupSession       *coreapi.BackupSession
	RestoreSession      *coreapi.RestoreSession
	BackupConfiguration *coreapi.BackupConfiguration
	FileInfos           []os.FileInfo

	ANDedLabelSelector []string
	ORedLabelSelector  []string
	ExcludeResources   []string

	Sanitize                bool
	OverrideResources       bool
	IncludeClusterResources bool
	ExcludeNamespaces       []string
	IncludeResources        []string
	IncludeNamespaces       []string

	StorageClassMappings    map[string]string
	StorageClassMappingsStr string
	RestorePVs              bool
}

func NewOptions() *Options {
	return &Options{
		WaitTimeout: 300,
		SetupOptions: restic.SetupOptions{
			ScratchDir:  restic.DefaultScratchDir,
			EnableCache: false,
		},
		BackupOptions: restic.BackupOptions{
			Host: apis.ComponentManifest,
		},
	}
}
