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

package filter

import (
	"gomodules.xyz/pointer"
	"k8s.io/utils/ptr"
)

type IncludeExclude struct {
	includes map[string]struct{}
	excludes map[string]struct{}
}

func NewIncludeExclude() *IncludeExclude {
	return &IncludeExclude{
		includes: make(map[string]struct{}),
		excludes: make(map[string]struct{}),
	}
}

func (f *IncludeExclude) Includes(items ...string) *IncludeExclude {
	for _, item := range items {
		f.includes[item] = struct{}{}
	}
	return f
}

func (f *IncludeExclude) Excludes(items ...string) *IncludeExclude {
	for _, item := range items {
		f.excludes[item] = struct{}{}
	}
	return f
}

func GetIncludeExcludeResources(includes, excludes []string) *IncludeExclude {
	f := NewIncludeExclude()
	f.Includes(includes...)
	for _, item := range excludes {
		if item == "*" {
			continue
		}
		f.Excludes(item)
	}
	return f
}

func (f *IncludeExclude) ShouldInclude(item string) bool {
	// Always excluded if in excludes.
	if _, blocked := f.excludes[item]; blocked {
		return false
	}
	// If no explicit includes or wildcard, include everything by default.
	return len(f.includes) == 0 || hasWildcard(f.includes) || exists(f.includes, item)
}

func hasWildcard(set map[string]struct{}) bool {
	_, ok := set["*"]
	return ok
}

func exists(set map[string]struct{}, item string) bool {
	_, ok := set[item]
	return ok
}

type GlobalIncludeExclude struct {
	resourceFilter          *IncludeExclude
	includeClusterResources *bool
	namespaceFilter         *IncludeExclude
}

func NewGlobalIncludeExclude(resourceFilter, namespaceFilter *IncludeExclude, includeClusterResources bool) *GlobalIncludeExclude {
	return &GlobalIncludeExclude{
		resourceFilter:          resourceFilter,
		namespaceFilter:         namespaceFilter,
		includeClusterResources: pointer.BoolP(includeClusterResources),
	}
}

func (g *GlobalIncludeExclude) ShouldIncludeResource(resource string, namespaced bool) bool {
	// If cluster-scoped and cluster resources not allowed, exclude.
	if !namespaced && !ptr.Deref(g.includeClusterResources, false) {
		return false
	}
	return g.resourceFilter.ShouldInclude(resource)
}

func (g *GlobalIncludeExclude) ShouldIncludeNamespace(namespace string) bool {
	return g.namespaceFilter.ShouldInclude(namespace)
}
