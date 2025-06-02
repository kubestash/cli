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

package dump

import (
	"sort"

	"kubestash.dev/cli/pkg/common"
)

type Priorities struct {
	HighPriorities []string
	LowPriorities  []string
}

var DefaultRestorePriorities = Priorities{
	HighPriorities: []string{
		"customresourcedefinitions.apiextensions.k8s.io",
		"namespaces",
		"storageclasses.storage.k8s.io",
		"volumesnapshotclass.snapshot.storage.k8s.io",
		"volumesnapshotcontents.snapshot.storage.k8s.io",
		"volumesnapshots.snapshot.storage.k8s.io",
		"persistentvolumes",
		"persistentvolumeclaims",
		"serviceaccounts",
		"secrets",
		"configmaps",
		"limitranges",
		"pods",
		"replicasets.apps",
		"clusterclasses.cluster.x-k8s.io",
		"endpoints",
		"services",
	},
	LowPriorities: []string{
		"clusters.cluster.x-k8s.io",
		"clusterresourcesets.addons.cluster.x-k8s.io",
		"apps.kappctrl.k14s.io",
		"packageinstalls.packaging.carvel.dev",
	},
}

func getOrderedResources(backupResources map[string]*common.ResourceItems) []string {
	priorities := map[string]struct{}{}
	for _, priority := range DefaultRestorePriorities.HighPriorities {
		priorities[priority] = struct{}{}
	}
	for _, priority := range DefaultRestorePriorities.LowPriorities {
		priorities[priority] = struct{}{}
	}

	// pick the prioritized resources out
	var orderedBackupResources []string
	for resource := range backupResources {
		if _, exist := priorities[resource]; exist {
			continue
		}
		orderedBackupResources = append(orderedBackupResources, resource)
	}
	// alphabetize resources in the backup
	sort.Strings(orderedBackupResources)

	list := append(DefaultRestorePriorities.HighPriorities, orderedBackupResources...)
	return append(list, DefaultRestorePriorities.LowPriorities...)
}
