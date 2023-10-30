/*
Copyright AppsCode Inc. and Contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	"kubestash.dev/apimachinery/apis/storage/v1alpha1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	ResourceKindBackendMeta = "BackendMeta"
)

// BackendMeta specifies the metadata for the BackupStorage
type BackendMeta struct {
	metav1.TypeMeta `json:",inline"`
	// CreationTimestamp is a timestamp representing the server time when this object was created.
	CreationTimestamp metav1.Time `json:"creationTimestamp,omitempty"`
	// OperatorVersion represents the version of the Operator when this object was created.
	OperatorVersion string `json:"operatorVersion,omitempty"`
	// Repositories holds the information of all Repositories using the BackupStorage.
	Repositories []v1alpha1.RepositoryInfo `json:"repositories,omitempty"`
}
