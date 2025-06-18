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
	"fmt"
	"strings"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"
	"kubestash.dev/cli/pkg/common"
	"sigs.k8s.io/yaml"
)

func (m *ResourceManager) getGVR(groupRes string) (schema.GroupVersionResource, error) {
	gr := schema.ParseGroupResource(groupRes)
	version, err := m.getPreferredVersion(gr)
	if err != nil {
		return schema.GroupVersionResource{}, fmt.Errorf("get preferred version for %s: %w", groupRes, err)
	}
	return schema.GroupVersionResource{Group: gr.Group, Version: version, Resource: gr.Resource}, nil
}

func (m *ResourceManager) getPreferredVersion(gr schema.GroupResource) (string, error) {
	groups, err := m.discoveryClient.ServerGroups()
	if err != nil {
		return "", fmt.Errorf("list API groups: %w", err)
	}
	for _, group := range groups.Groups {
		if group.Name != gr.Group {
			continue
		}
		for _, ver := range group.Versions {
			resList, err := m.discoveryClient.ServerResourcesForGroupVersion(ver.GroupVersion)
			if err != nil {
				continue
			}
			for _, r := range resList.APIResources {
				if r.Name == gr.Resource {
					return ver.Version, nil
				}
			}
		}
	}
	return "", fmt.Errorf("resource %s/%s not found in discovery", gr.Group, gr.Resource)
}

func (m *ResourceManager) unmarshal(path string) (*unstructured.Unstructured, error) {
	data, err := m.reader.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file %s: %w", path, err)
	}
	obj := &unstructured.Unstructured{}
	if err := yaml.Unmarshal(data, &obj.Object); err != nil {
		return nil, fmt.Errorf("unmarshal %s: %w", path, err)
	}
	return obj, nil
}

// validResource skips subresources and resources without get+list verbs.
func validResource(res metav1.APIResource) bool {
	if strings.Contains(res.Name, "/") {
		return false
	}
	return sets.NewString(res.Verbs...).HasAll("get", "list")
}

func parseSCMappings(input string) map[string]string {
	m := map[string]string{}
	for _, pair := range strings.Split(input, ",") {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) == 2 {
			m[parts[0]] = parts[1]
		}
	}
	return m
}

func labelsToStrings(labels map[string]string) []string {
	out := make([]string, 0, len(labels))
	for k, v := range labels {
		out = append(out, fmt.Sprintf("%s:%s", k, v))
	}
	return out
}

func matchesAny(labels, selectors []string) bool {
	if len(selectors) == 0 {
		return true
	}
	set := sets.NewString(labels...)
	for _, sel := range selectors {
		if set.Has(sel) {
			return true
		}
	}
	return false
}

func matchesAll(labels, selectors []string) bool {
	if len(selectors) == 0 {
		return true
	}
	set := sets.NewString(labels...)
	for _, sel := range selectors {
		if !set.Has(sel) {
			return false
		}
	}
	return true
}

func getItemKey(obj *unstructured.Unstructured) common.ItemKey {
	return common.ItemKey{
		Resource:  resourceKey(obj),
		Namespace: obj.GetNamespace(),
		Name:      obj.GetName(),
	}
}

func resourceKey(obj runtime.Object) string {
	gvk := obj.GetObjectKind().GroupVersionKind()
	return fmt.Sprintf("%s/%s", gvk.GroupVersion().String(), gvk.Kind)
}

func toStrings(labels map[string]string) []string {
	out := make([]string, 0, len(labels))
	for key, val := range labels {
		out = append(out, fmt.Sprintf("%s:%s", key, val))
	}
	return out
}

func isCompleted(obj *unstructured.Unstructured) (bool, error) {
	switch obj.GetKind() {
	case "Pod":
		phase, _, err := unstructured.NestedString(obj.Object, "status", "phase")
		if err != nil {
			return false, err
		}
		return phase == string(v1.PodSucceeded) || phase == string(v1.PodFailed), nil
	case "Job":
		ct, found, err := unstructured.NestedString(obj.Object, "status", "completionTime")
		if err != nil {
			return false, err
		}
		return found && ct != "", nil
	}
	return false, nil
}
