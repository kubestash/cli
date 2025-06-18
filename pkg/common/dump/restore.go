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
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/klog/v2"
	"kubestash.dev/cli/pkg/common"
	"sigs.k8s.io/yaml"
)

func (m *ResourceManager) RestoreManifests(ctx context.Context) error {
	var err error
	m.backupResources, err = m.parseItems()
	if err != nil {
		return fmt.Errorf("failed to parse items: %w", err)
	}

	// 1. Restore CRD First
	if err := m.restoreResourceType(ctx, common.CustomResourceDefinitions.String()); err != nil {
		return err
	}

	// 2. Restore other resources in order
	ordered := getOrderedResources(m.backupResources)
	for _, gr := range ordered {
		if gr == common.CustomResourceDefinitions.String() {
			continue
		}
		if err := m.restoreResourceType(ctx, gr); err != nil {
			return err
		}
	}

	fmt.Printf("Total Successfully restored %d items", len(m.restoredItems))
	return nil
}

func (m *ResourceManager) restoreResourceType(ctx context.Context, groupRes string) error {
	rItems, ok := m.backupResources[groupRes]
	if !ok {
		klog.V(2).Infof("no backups for %s", groupRes)
		return nil
	}
	ns, err := m.isNamespaced(groupRes)
	if err != nil {
		return fmt.Errorf("failed to determine if %s is namespaced: %w", groupRes, err)
	}
	if !m.filter.ShouldIncludeResource(groupRes, ns) {
		klog.V(2).Infof("skipping %s by filter", groupRes)
		return nil
	}

	restorable := m.getRestoreableItems(rItems)
	for namespace, items := range restorable.SelectedItemsByNamespace {
		if namespace != "" {
			if err := m.ensureNamespace(ctx, namespace); err != nil {
				return err
			}
		}
		for _, item := range items {
			if err := m.applyItem(ctx, groupRes, item); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *ResourceManager) applyItem(ctx context.Context, groupRes string, itm common.RestoreableItem) error {
	obj, err := m.unmarshal(itm.Path)
	if err != nil {
		klog.Errorf("unmarshal %s: %v", itm.Path, err)
		return err
	}

	key := getItemKey(obj)
	if _, done := m.restoredItems[key]; done {
		klog.V(3).Infof("already restored %s", key)
		return nil
	}
	if !m.shouldRestore(obj) {
		klog.V(3).Infof("filtered %s", key)
		return nil
	}
	if done, err := isCompleted(obj); err != nil {
		return err
	} else if done {
		klog.Infof("skipping completed %s", key)
		return nil
	}

	gvr, err := m.getGVR(groupRes)
	if err != nil {
		return err
	}

	if m.DryRunDir != "" {
		dryRunPath := filepath.Join(m.DryRunDir, groupRes)
		namespaceOfObject := obj.GetNamespace()
		if namespaceOfObject == "" {
			dryRunPath = filepath.Join(dryRunPath, common.ClusterScopedDir, obj.GetName())
		} else {
			dryRunPath = filepath.Join(dryRunPath, common.NamespaceScopedDir, namespaceOfObject, obj.GetName())
		}
		jsonBytes, err := runtime.Encode(unstructured.UnstructuredJSONScheme, obj)
		if err != nil {
			return err
		}
		yamlBytes, err := yaml.JSONToYAML(jsonBytes)
		if err != nil {
			return err
		}
		dryRunPath = dryRunPath + ".yaml"
		if err := m.writer.Write(dryRunPath, yamlBytes); err != nil {
			return err
		}
		return nil
	}

	sObj, err := m.sanitizerFactory(gvr.Resource).Sanitize(obj.Object)
	if err != nil {
		return fmt.Errorf("sanitize %s: %w", key, err)
	}

	if m.StorageClassMappingsStr != "" {
		spec := sObj["spec"].(map[string]interface{})
		if spec["storageClassName"] == nil {
			oldStorageClassName := spec["storageClassName"].(string)
			spec["storageClassName"] = m.StorageClassMappings[oldStorageClassName]
		}
		sObj["spec"] = spec
	}

	obj.Object = sObj
	if err := m.createIfMissing(ctx, gvr, obj); err != nil {
		return err
	}
	return nil
}

func (m *ResourceManager) ensureNamespace(ctx context.Context, ns string) error {
	gvr := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "namespaces"}
	ri := m.dynamicClient.Resource(gvr)
	if exists, _ := m.exists(ctx, ri, ns); exists {
		klog.V(2).Infof("namespace %s exists", ns)
		return nil
	}
	obj := &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]interface{}{"name": ns}}}
	key := getItemKey(obj)
	if _, done := m.restoredItems[key]; done {
		klog.V(3).Infof("already restored %s", key)
		return nil
	}
	if _, err := ri.Create(ctx, obj, metav1.CreateOptions{}); err != nil && !errors.IsAlreadyExists(err) {
		return fmt.Errorf("create namespace %s: %w", ns, err)
	}
	m.restoredItems[getItemKey(obj)] = common.RestoredItemStatus{Action: "Created"}
	klog.Infof("namespace created %s", ns)
	return nil
}

func (m *ResourceManager) createIfMissing(ctx context.Context, gvr schema.GroupVersionResource, obj *unstructured.Unstructured) error {
	ri := m.dynamicClient.Resource(gvr).Namespace(obj.GetNamespace())
	if exists, err := m.exists(ctx, ri, obj.GetName()); err != nil {
		return err
	} else if exists {
		klog.V(2).Infof("exists %s/%s", gvr.Resource, obj.GetName())
		m.restoredItems[getItemKey(obj)] = common.RestoredItemStatus{ItemExists: true}
		return nil
	}
	if _, err := ri.Create(ctx, obj, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("create %s/%s: %w", gvr.Resource, obj.GetName(), err)
	}
	m.restoredItems[getItemKey(obj)] = common.RestoredItemStatus{Action: "Created"}
	klog.Infof("created %s/%s", gvr.Resource, obj.GetName())
	return nil
}

func (m *ResourceManager) exists(ctx context.Context, ri dynamic.ResourceInterface, name string) (bool, error) {
	_, err := ri.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (m *ResourceManager) shouldRestore(obj *unstructured.Unstructured) bool {
	if ns := obj.GetNamespace(); ns != "" && !m.filter.ShouldIncludeNamespace(ns) {
		fmt.Printf("skipping %s by filter\n", obj.GetName())
		return false
	}
	labels := toStrings(obj.GetLabels())
	return matchesAny(labels, m.Options.ORedLabelSelector) && matchesAll(labels, m.Options.ANDedLabelSelector)
}

func (m *ResourceManager) isNamespaced(groupRes string) (bool, error) {
	g, err := m.getGVR(groupRes)
	if err != nil {
		return false, err
	}
	gv := g.GroupVersion()
	resList, err := m.discoveryInterface.ServerResourcesForGroupVersion(gv.String())
	if err != nil {
		return false, err
	}
	for _, r := range resList.APIResources {
		if r.Name == g.Resource {
			return r.Namespaced, nil
		}
	}
	return false, fmt.Errorf("%s not found", groupRes)
}

func (m *ResourceManager) parseItems() (map[string]*common.ResourceItems, error) {
	resources := make(map[string]*common.ResourceItems)

	for componentName, component := range m.Snapshot.Status.Components {
		for _, resticStat := range component.ResticStats {
			baseDir := filepath.Join(m.Options.DataDir, m.SnapshotName, componentName, resticStat.HostPath)
			entries, err := m.reader.ReadDir(baseDir)
			if err != nil {
				return nil, fmt.Errorf("failed to read backup directory: %w", err)
			}

			for _, entry := range entries {
				groupResource := entry.Name()
				ri := &common.ResourceItems{
					GroupResource:    groupResource,
					ItemsByNamespace: map[string][]string{},
				}
				addResourceItems := func(ns, nsDir string) error {
					items, err := m.getResourceItemsForScope(nsDir)
					if err != nil {
						return err
					}
					if len(items) > 0 {
						ri.ItemsByNamespace[ns] = items
					}
					return nil
				}
				s := filepath.Join(baseDir, groupResource)
				scopes := []struct{ dir, ns string }{
					{dir: filepath.Join(s, common.ClusterScopedDir), ns: ""},
					{dir: filepath.Join(s, common.NamespaceScopedDir), ns: "*"},
				}

				for _, scope := range scopes {
					info, err := os.Stat(scope.dir)
					if err != nil || !info.IsDir() {
						continue
					}

					if scope.ns == "" { // cluster-scoped items
						if err := addResourceItems("", scope.dir); err != nil {
							return nil, err
						}
					} else { // namespace-scoped: read each namespace subdir
						nsDirs, err := m.reader.ReadDir(scope.dir)
						if err != nil {
							return nil, fmt.Errorf("read namespaces in %s: %w", scope.dir, err)
						}
						for _, nsInfo := range nsDirs {
							if !nsInfo.IsDir() {
								continue
							}
							ns := nsInfo.Name()
							if err := addResourceItems(ns, filepath.Join(scope.dir, ns)); err != nil {
								return nil, err
							}
						}
					}
				}
				resources[groupResource] = ri
			}
		}
	}
	return resources, nil
}

func (m *ResourceManager) getRestoreableItems(r *common.ResourceItems) common.RestoreableResource {
	restorable := common.RestoreableResource{
		Resource:                 r.GroupResource,
		SelectedItemsByNamespace: make(map[string][]common.RestoreableItem),
	}
	for componentName, component := range m.Snapshot.Status.Components {
		for _, resticStat := range component.ResticStats {
			baseDir := filepath.Join(m.Options.DataDir, m.SnapshotName, componentName, resticStat.HostPath)
			resourceForPath := filepath.Join(baseDir, r.GroupResource)
			for namespace, items := range r.ItemsByNamespace {
				identifier := common.NamespaceScopedDir
				if namespace == "" {
					identifier = common.ClusterScopedDir
				}
				for _, item := range items {
					itemPath := filepath.Join(resourceForPath, identifier, namespace, item)
					selectedItem := common.RestoreableItem{
						Path:            itemPath,
						Name:            strings.TrimSuffix(item, ".yaml"),
						TargetNamespace: namespace, // Currently we're considering only the backed up namespace.
					}
					restorable.SelectedItemsByNamespace[namespace] = append(restorable.SelectedItemsByNamespace[namespace], selectedItem)
				}
			}
		}
	}
	return restorable
}

func (m *ResourceManager) getResourceItemsForScope(dir string) ([]string, error) {
	files, err := m.reader.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory %s: %w", dir, err)
	}
	var items []string
	for _, file := range files {
		if file.IsDir() {
			klog.Infoln("Skipping directory:", file.Name())
			continue
		}

		items = append(items, file.Name())
	}
	return items, nil
}
