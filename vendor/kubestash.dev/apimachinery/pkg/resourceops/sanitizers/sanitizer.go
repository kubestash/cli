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

package sanitizers

import (
	"kubestash.dev/apimachinery/apis"
)

type Sanitizer interface {
	Sanitize(in map[string]any) (map[string]any, error)
}

func NewSanitizer(resource string) Sanitizer {
	switch resource {
	case apis.Pods.Resource:
		return newPodSanitizer()
	case apis.PersistentVolumeClaims.Resource:
		return newPVCSanitizer()
	case apis.Statefulsets.Resource, apis.Deployments.Resource, apis.ReplicaSets.Resource,
		apis.DaemonSets.Resource, apis.ReplicationControllers.Resource, apis.Jobs.Resource:
		return newWorkloadSanitizer()
	default:
		return newDefaultSanitizer()
	}
}

type defaultSanitizer struct{}

func newDefaultSanitizer() Sanitizer {
	return defaultSanitizer{}
}

func (s defaultSanitizer) Sanitize(in map[string]any) (map[string]any, error) {
	ms := newMetadataSanitizer()
	in, err := ms.Sanitize(in)
	if err != nil {
		return nil, err
	}
	return in, nil
}
