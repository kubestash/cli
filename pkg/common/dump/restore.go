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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	utilErr "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/dynamic"
	"k8s.io/klog/v2"
	"kubestash.dev/apimachinery/apis"
	"kubestash.dev/cli/pkg/common"
	"sigs.k8s.io/yaml"
)

func (m *ResourceManager) RestoreManifests(ctx context.Context) error {
	var err error
	if m.backupResources, err = m.parseItems(); err != nil {
		klog.Infof("Failed to parse items: %v", err)
		return err
	}

	var errs []error
	for m.currentIteration = 1; m.currentIteration <= m.maxIterations; m.currentIteration += 1 {
		errs = []error{}
		needIteration := false
		klog.Infof("Iteration %d: Starting restore process.", m.currentIteration)
		// 1. Restore CRDs
		if err = m.restoreResourceType(ctx, apis.CustomResourceDefinitions.String()); err != nil {
			needIteration = true
			errs = append(errs, err)
		}
		// 2. Restore remaining resources
		if err = m.restoreResourcesInOrder(ctx); err != nil {
			needIteration = true
			errs = append(errs, err)
		}
		if !needIteration {
			klog.Infof("Iteration %d: All resources restored successfully.", m.currentIteration)
			break
		}
	}

	// 3. Set Owner References to restored resources
	if m.DryRunDir == "" {
		err = m.setOwnerReferences(ctx)
		if err != nil {
			errs = append(errs, err)
		}
	} else {
		klog.Infof("Skipping owner references update as dry-run-dir set to %v.", m.DryRunDir)
	}

	klog.Warningf("Restore finished with errors across %d iteration(s). Total restored: %d", m.currentIteration, len(m.restoredItems))
	if len(errs) > 0 {
		return fmt.Errorf("failed to restore resources, please check the logs for more details")
	}

	return nil
}

func (m *ResourceManager) restoreResourcesInOrder(ctx context.Context) error {
	ordered := getOrderedResources(m.backupResources)

	var errs []error
	for _, gr := range ordered {
		if gr == apis.CustomResourceDefinitions.String() {
			continue
		}

		err := m.restoreResourceType(ctx, gr)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return utilErr.NewAggregate(errs)
}

func (m *ResourceManager) restoreResourceType(ctx context.Context, groupRes string) error {
	rItems, ok := m.backupResources[groupRes]
	if !ok {
		klog.Infof("Iteration %d: no backups for %s", m.currentIteration, groupRes)
		return nil
	}
	ns, err := m.isNamespaced(groupRes)
	if err != nil {
		klog.Infof("Iteration %d: failed to determine if %s is namespaced: %v", m.currentIteration, groupRes, err)
		return err
	}

	if !m.filter.ShouldIncludeResource(groupRes, ns) {
		klog.Infof("Iteration %d: skipping %s by filter", m.currentIteration, groupRes)
		return nil
	}

	selectedItemsByNamespace := m.getRestoreableItems(rItems)
	var errs []error

	for namespace, items := range selectedItemsByNamespace {
		if namespace != "" {
			err = m.ensureNamespace(ctx, namespace)
			if err != nil {
				errs = append(errs, err)
				continue
			}
		}
		for _, item := range items {
			err = m.applyItem(ctx, groupRes, item)
			if err != nil {
				errs = append(errs, err)
				klog.Infof("Iteration %d: failed to apply GroupResource: %s, Item: %s", m.currentIteration, groupRes, item)
				if m.currentIteration < m.maxIterations {
					continue
				}
			}
		}
	}
	return utilErr.NewAggregate(errs)
}

func (m *ResourceManager) applyItem(ctx context.Context, groupRes string, itm common.RestoreableItem) error {
	obj, err := m.unmarshal(itm.Path)
	if err != nil {
		klog.Infof("Iteration %d: unmarshal %s: %v", m.currentIteration, itm.Path, err)
		return err
	}
	gvr, err := m.getGVR(groupRes)
	if err != nil {
		klog.Infof("Iteration %d: failed to determine GVR for %s: %v", m.currentIteration, groupRes, err)
		return err
	}

	key := getItemKey(obj)
	if _, done := m.restoredItems[key]; done {
		klog.V(3).Infof("Iteration %d: already restored %s", m.currentIteration, key)
		return nil
	}
	if !m.shouldRestore(obj) {
		klog.V(3).Infof("Iteration %d: filtered %s", m.currentIteration, key)
		return nil
	}
	if done, err := isCompleted(obj); err != nil {
		klog.Infof("Iteration %d: failed to determine if completed, GVR: %s, Name: %s, Error: %v", m.currentIteration, gvr, obj.GetName(), err)
		return err
	} else if done {
		klog.Infof("Iteration %d: skipping completed %s", m.currentIteration, key)
		return nil
	}

	sObj, err := m.sanitizerFactory(gvr.Resource).Sanitize(obj.Object)
	if err != nil {
		klog.Infof("Iteration %d: failed to sanitize %s, error: %v", m.currentIteration, key, err)
		return err
	}

	if gvr.Resource == apis.PersistentVolumeClaims.Resource &&
		m.StorageClassMappingsStr != "" {
		if spec, ok := sObj["spec"].(map[string]interface{}); ok && spec != nil {
			sObj["spec"] = m.mapStorageClass(spec)
		}
	}

	if m.DryRunDir != "" {
		if err := m.downloadTheItem(groupRes, obj); err != nil {
			klog.Infof("Iteration %d: failed to download item in dry-run-dir, error: %v.", m.currentIteration, err)
			return err
		} else {
			klog.Infof("Iteration %d: item successfully downloaded in dry-run-dir.", m.currentIteration)
		}
		return nil
	}

	obj.Object = sObj
	if err := m.createIfMissing(ctx, gvr, obj); err != nil {
		klog.Infof("Iteration %d: failed to restore GVR: %s, Name: %s, Error: %v", m.currentIteration, gvr, obj.GetName(), err)
		return err
	}
	return nil
}

func (m *ResourceManager) downloadTheItem(groupRes string, obj *unstructured.Unstructured) error {
	dryRunPath := filepath.Join(m.DryRunDir, groupRes)
	klog.Infof("Iteration %d: downloading item in dry-run dir: %s, GroupResource: %s, Name: %s", m.currentIteration, m.DryRunDir, groupRes, obj.GetName())
	namespaceOfObject := obj.GetNamespace()
	if namespaceOfObject == "" {
		dryRunPath = filepath.Join(dryRunPath, apis.ClusterScopedDir, obj.GetName())
	} else {
		dryRunPath = filepath.Join(dryRunPath, apis.NamespaceScopedDir, namespaceOfObject, obj.GetName())
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

func (m *ResourceManager) mapStorageClass(spec map[string]interface{}) map[string]interface{} {
	if oldStorageClassName, ok := spec["storageClassName"].(string); ok {
		if _, exist := m.StorageClassMappings[oldStorageClassName]; exist {
			spec["storageClassName"] = m.StorageClassMappings[oldStorageClassName]
		}
	}
	return spec
}

func (m *ResourceManager) ensureNamespace(ctx context.Context, ns string) error {
	gvr := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "namespaces"}
	ri := m.dynamicClient.Resource(gvr)
	if exists, _ := m.exists(ctx, ri, ns); exists {
		klog.V(2).Infof("Iteration %d: namespace %s exists", m.currentIteration, ns)
		return nil
	}
	obj := &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]interface{}{"name": ns}}}
	key := getItemKey(obj)
	if _, done := m.restoredItems[key]; done {
		klog.V(3).Infof("Iteration %d: already restored %s", m.currentIteration, key)
		return nil
	}
	if _, err := ri.Create(ctx, obj, metav1.CreateOptions{}); err != nil && !errors.IsAlreadyExists(err) {
		klog.Infof("Iteration %d: Error creating namespace %s: %v", m.currentIteration, key, err)
		return err
	}
	m.restoredItems[getItemKey(obj)] = common.RestoredItemStatus{Action: "Created"}
	klog.Infof("Iteration %d: namespace created %s", m.currentIteration, ns)
	return nil
}

func (m *ResourceManager) createIfMissing(ctx context.Context, gvr schema.GroupVersionResource, obj *unstructured.Unstructured) error {
	ownerRef := obj.GetOwnerReferences()
	ri := m.dynamicClient.Resource(gvr).Namespace(obj.GetNamespace())
	if exists, err := m.exists(ctx, ri, obj.GetName()); err != nil {
		return err
	} else if exists {
		klog.Infof("Iteration %d: exists %s/%s", m.currentIteration, gvr.Resource, obj.GetName())
		m.restoredItems[getItemKey(obj)] = common.RestoredItemStatus{ItemExists: true, GVR: gvr, OwnerReferences: ownerRef}
		return nil
	}

	obj.SetOwnerReferences(nil)
	if _, err := ri.Create(ctx, obj, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("iteration %d: error creating %s/%s: %w", m.currentIteration, gvr.Resource, obj.GetName(), err)
	}
	m.restoredItems[getItemKey(obj)] = common.RestoredItemStatus{Action: "Created", GVR: gvr, OwnerReferences: ownerRef}
	klog.Infof("Iteration %d: created %s/%s", m.currentIteration, gvr.Resource, obj.GetName())
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

func (m *ResourceManager) setOwnerReferences(ctx context.Context) error {
	klog.Infof("Iteration %d: Applying owner references to %d resources...", m.currentIteration, len(m.restoredItems))
	var errs []error
	for objectKey, infos := range m.restoredItems {
		intendedOwners := infos.OwnerReferences
		if len(intendedOwners) == 0 {
			continue
		}

		validRelinkedOwners := m.getValidRelinkedOwners(ctx, objectKey, intendedOwners)
		if len(validRelinkedOwners) == 0 {
			klog.Warningf("Iteration %d: None of the intended owners for %s/%s could be found in the cluster. Skipping patch.", m.currentIteration, objectKey.Resource, objectKey.Name)
			continue
		}

		patchPayload := map[string]interface{}{
			"metadata": map[string]interface{}{
				"ownerReferences": validRelinkedOwners,
			},
		}
		patchBytes, err := json.Marshal(patchPayload)
		if err != nil {
			errs = append(errs, err)
			klog.Errorf("Iteration %d: Failed to create patch JSON for %q: %v", m.currentIteration, objectKey.Name, err)
			continue
		}

		ri := m.dynamicClient.Resource(infos.GVR).Namespace(objectKey.Namespace)

		klog.Infof("Iteration %d: Patching %s/%s with %d found owner(s).", m.currentIteration, objectKey.Resource, objectKey.Name, len(validRelinkedOwners))
		_, err = ri.Patch(ctx, objectKey.Name, types.MergePatchType, patchBytes, metav1.PatchOptions{})
		if err != nil {
			errs = append(errs, err)
			klog.Errorf("Iteration %d: Failed to patch owner references for %q: %v", m.currentIteration, objectKey.Name, err)
		}
	}
	return utilErr.NewAggregate(errs)
}

func (m *ResourceManager) getValidRelinkedOwners(ctx context.Context, childKey common.ItemKey, originalOwners []metav1.OwnerReference) []metav1.OwnerReference {
	var validOwners []metav1.OwnerReference
	for _, owner := range originalOwners {
		ownerGVK := schema.FromAPIVersionAndKind(owner.APIVersion, owner.Kind)
		ownerResourceKeyStr := fmt.Sprintf("%s/%s", ownerGVK.GroupVersion().String(), ownerGVK.Kind)
		var ownerKey common.ItemKey

		found := false
		namespacedKey := common.ItemKey{Resource: ownerResourceKeyStr, Namespace: childKey.Namespace, Name: owner.Name}
		if _, ok := m.restoredItems[namespacedKey]; ok {
			ownerKey = namespacedKey
			found = true
		} else {
			clusterScopedKey := common.ItemKey{Resource: ownerResourceKeyStr, Name: owner.Name}
			if _, ok := m.restoredItems[clusterScopedKey]; ok {
				ownerKey = clusterScopedKey
				found = true
			}
		}

		if found {
			ownerGVR := m.restoredItems[ownerKey].GVR
			ownerNamespace := ownerKey.Namespace
			ri := m.dynamicClient.Resource(ownerGVR).Namespace(ownerNamespace)
			if existingObj, err := ri.Get(ctx, ownerKey.Name, metav1.GetOptions{}); err == nil {
				owner.UID = existingObj.GetUID()
				validOwners = append(validOwners, owner)
				klog.Infof("Iteration %d: Owner %s %s was found in the cluster as an owner for %s.", m.currentIteration, owner.Kind, owner.Name, childKey.Name)
				continue
			}
		}
		klog.Warningf("Iteration %d: Owner %s %s was not found in the cluster. It will be omitted as an owner for %s.", m.currentIteration, owner.Kind, owner.Name, childKey.Name)
	}

	return validOwners
}

func (m *ResourceManager) shouldRestore(obj *unstructured.Unstructured) bool {
	if ns := obj.GetNamespace(); ns != "" && !m.filter.ShouldIncludeNamespace(ns) {
		klog.Infof("Iteration %d: skipping %s by filter\n", m.currentIteration, obj.GetName())
		return false
	}
	labels := LabelsToStrings(obj.GetLabels())
	return matchesAny(labels, m.Options.ORedLabelSelectors) && matchesAll(labels, m.Options.ANDedLabelSelectors)
}

func (m *ResourceManager) isNamespaced(groupRes string) (bool, error) {
	g, err := m.getGVR(groupRes)
	if err != nil {
		return false, err
	}
	gv := g.GroupVersion()
	resList, err := m.discoveryClient.ServerResourcesForGroupVersion(gv.String())
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
					{dir: filepath.Join(s, apis.ClusterScopedDir), ns: ""},
					{dir: filepath.Join(s, apis.NamespaceScopedDir), ns: "*"},
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

func (m *ResourceManager) getRestoreableItems(r *common.ResourceItems) map[string][]common.RestoreableItem {
	selectedItemsByNamespace := make(map[string][]common.RestoreableItem)
	for componentName, component := range m.Snapshot.Status.Components {
		for _, resticStat := range component.ResticStats {
			baseDir := filepath.Join(m.Options.DataDir, m.SnapshotName, componentName, resticStat.HostPath)
			resourceForPath := filepath.Join(baseDir, r.GroupResource)
			for namespace, items := range r.ItemsByNamespace {
				identifier := apis.NamespaceScopedDir
				if namespace == "" {
					identifier = apis.ClusterScopedDir
				}
				for _, item := range items {
					itemPath := filepath.Join(resourceForPath, identifier, namespace, item)
					selectedItem := common.RestoreableItem{
						Path:            itemPath,
						Name:            strings.TrimSuffix(item, ".yaml"),
						TargetNamespace: namespace, // Currently we're considering only the backed up namespace.
					}
					selectedItemsByNamespace[namespace] = append(selectedItemsByNamespace[namespace], selectedItem)
				}
			}
		}
	}
	return selectedItemsByNamespace
}

func (m *ResourceManager) getResourceItemsForScope(dir string) ([]string, error) {
	files, err := m.reader.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("iteration %d: failed to read directory %s: %w", m.currentIteration, dir, err)
	}
	var items []string
	for _, file := range files {
		if file.IsDir() {
			klog.Infoln("Skipping directory:", m.currentIteration, file.Name())
			continue
		}

		items = append(items, file.Name())
	}
	return items, nil
}
