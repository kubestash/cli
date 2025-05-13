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
	"testing"
)

func TestIncludeExcludeFilter_Default(t *testing.T) {
	f := NewIncludeExclude()
	if !f.ShouldInclude("anything") {
		t.Errorf("expected default to include everything, got exclusion")
	}
}

func TestIncludeExcludeFilter_IncludesOnly(t *testing.T) {
	f := NewIncludeExclude().Includes("a", "b")
	if !f.ShouldInclude("a") || !f.ShouldInclude("b") {
		t.Errorf("expected includes to allow listed items")
	}
	if f.ShouldInclude("c") {
		t.Errorf("expected unlisted item to be excluded when includes are set")
	}
}

func TestIncludeExcludeFilter_ExcludesOnly(t *testing.T) {
	f := NewIncludeExclude().Excludes("x", "y")
	if f.ShouldInclude("x") || f.ShouldInclude("y") {
		t.Errorf("expected excludes to block listed items")
	}
	if !f.ShouldInclude("z") {
		t.Errorf("expected non-excluded item to be included by default")
	}
}

func TestIncludeExcludeFilter_Wildcard(t *testing.T) {
	f := NewIncludeExclude().Includes("*")
	if !f.ShouldInclude("foo") || !f.ShouldInclude("bar") {
		t.Errorf("expected wildcard include to include everything")
	}
}

func TestGetIncludeExcludeResources(t *testing.T) {
	f := GetIncludeExcludeResources([]string{"a", "*"}, []string{"b", "*"})
	if !f.ShouldInclude("a") {
		t.Errorf("expected 'a' included")
	}
	if f.ShouldInclude("b") {
		t.Errorf("expected 'b' excluded")
	}
	if !f.ShouldInclude("c") {
		t.Errorf("expected wildcard include to include 'c'")
	}
}

func TestGlobalIncludeExclude(t *testing.T) {
	resFilter := NewIncludeExclude().Includes("pods", "nodes")
	nsFilter := NewIncludeExclude().Excludes("kube-system")
	gFalse := NewGlobalIncludeExclude(resFilter, nsFilter, false)
	// cluster-scoped resources should be blocked when flag is false
	if gFalse.ShouldIncludeResource("nodes", false) {
		t.Errorf("expected cluster-scoped 'nodes' excluded when flag=false")
	}
	// namespaced resource included if in resourceFilter
	if !gFalse.ShouldIncludeResource("pods", true) {
		t.Errorf("expected 'pods' included when namespaced = true and in filter")
	}
	// namespace exclusion works
	if gFalse.ShouldIncludeNamespace("kube-system") {
		t.Errorf("expected namespace 'kube-system' excluded")
	}

	// cluster-scoped allowed when flag=true
	gTrue := NewGlobalIncludeExclude(resFilter, nsFilter, true)
	if !gTrue.ShouldIncludeResource("nodes", false) {
		t.Errorf("expected 'nodes' included when flag=true")
	}

	// cluster-scoped = "customresourcedefinitions"
	resFilter = NewIncludeExclude().Includes("*")
	nsFilter = NewIncludeExclude().Excludes("demo", "kubedb", "stash")
	gTrue = NewGlobalIncludeExclude(resFilter, nsFilter, true)
	if !gTrue.ShouldIncludeResource("customresourcedefinitions", false) {
		t.Errorf("expected 'customresourcedefinitions' included when flag=true")
	}

	// cluster-scoped = "customresourcedefinitions" but, includeClusterResources = false
	resFilter = NewIncludeExclude().Includes("customresourcedefinitions")
	nsFilter = NewIncludeExclude().Excludes("*")
	gTrue = NewGlobalIncludeExclude(resFilter, nsFilter, false)
	if !gTrue.ShouldIncludeResource("customresourcedefinitions", true) {
		t.Errorf("expected 'customresourcedefinitions' included when flag=true")
	}
}
