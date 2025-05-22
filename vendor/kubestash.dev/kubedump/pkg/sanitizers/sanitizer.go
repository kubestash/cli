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
	"kubestash.dev/kubedump/pkg/common"
)

type Sanitizer interface {
	Sanitize(in map[string]interface{}) (map[string]interface{}, error)
}

func NewSanitizer(resource string) Sanitizer {
	switch resource {
	case common.Pods.Resource:
		return newPodSanitizer()
	case common.PersistentVolumeClaims.Resource:
		return newPVCSanitizer()
	case common.Statefulsets.Resource, common.Deployments.Resource, common.ReplicaSets.Resource,
		common.DaemonSets.Resource, common.ReplicationControllers.Resource, common.Jobs.Resource:
		return newWorkloadSanitizer()
	default:
		return newDefaultSanitizer()
	}
}

type defaultSanitizer struct{}

func newDefaultSanitizer() Sanitizer {
	return defaultSanitizer{}
}

func (s defaultSanitizer) Sanitize(in map[string]interface{}) (map[string]interface{}, error) {
	ms := newMetadataSanitizer()
	in, err := ms.Sanitize(in)
	if err != nil {
		return nil, err
	}
	return in, nil
}
