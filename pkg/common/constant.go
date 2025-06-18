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

import "k8s.io/apimachinery/pkg/runtime/schema"

const (
	ClusterScopedDir   = "cluster"
	NamespaceScopedDir = "namespaces"
)

var (
	ClusterRoleBindings       = schema.GroupResource{Group: "rbac.authorization.k8s.io", Resource: "clusterrolebindings"}
	ClusterRoles              = schema.GroupResource{Group: "rbac.authorization.k8s.io", Resource: "clusterroles"}
	CustomResourceDefinitions = schema.GroupResource{Group: "apiextensions.k8s.io", Resource: "customresourcedefinitions"}
	DaemonSets                = schema.GroupResource{Group: "apps", Resource: "daemonsets"}
	Deployments               = schema.GroupResource{Group: "apps", Resource: "deployments"}
	Jobs                      = schema.GroupResource{Group: "batch", Resource: "jobs"}
	Namespaces                = schema.GroupResource{Group: "", Resource: "namespaces"}
	PersistentVolumeClaims    = schema.GroupResource{Group: "", Resource: "persistentvolumeclaims"}
	PersistentVolumes         = schema.GroupResource{Group: "", Resource: "persistentvolumes"}
	Pods                      = schema.GroupResource{Group: "", Resource: "pods"}
	ReplicationControllers    = schema.GroupResource{Group: "", Resource: "replicationcontrollers"}
	ReplicaSets               = schema.GroupResource{Group: "apps", Resource: "replicasets"}
	ServiceAccounts           = schema.GroupResource{Group: "", Resource: "serviceaccounts"}
	Secrets                   = schema.GroupResource{Group: "", Resource: "secrets"}
	Statefulsets              = schema.GroupResource{Group: "apps", Resource: "statefulsets"}
	VolumeSnapshotClasses     = schema.GroupResource{Group: "snapshot.storage.k8s.io", Resource: "volumesnapshotclasses"}
	VolumeSnapshots           = schema.GroupResource{Group: "snapshot.storage.k8s.io", Resource: "volumesnapshots"}
	VolumeSnapshotContents    = schema.GroupResource{Group: "snapshot.storage.k8s.io", Resource: "volumesnapshotcontents"}
	PriorityClasses           = schema.GroupResource{Group: "scheduling.k8s.io", Resource: "priorityclasses"}
)

var DefaultNonRestorableResources = []string{
	"nodes",
	"events",
	"events.events.k8s.io",
	"storage",
	"csinodes.storage.k8s.io",
	"volumeattachments.storage.k8s.io",

	// kubestash specific
	"backupsessions.core.kubestash.com",
	"backupverificationsession.core.kubestash.com",
	"backupverifier.core.kubestash.com",
	"repositories.storage.kubestash.com",
	"restoresessions.core.kubestash.com",
	"snapshots.storage.kubestash.com",
}
