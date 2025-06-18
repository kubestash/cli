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
	"path/filepath"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	"kubestash.dev/cli/pkg/common"
	"kubestash.dev/cli/pkg/filter"
	"kubestash.dev/cli/pkg/sanitizers"
	yaml "sigs.k8s.io/yaml/goyaml.v2"
)

type ResourceManager struct {
	*common.Options

	// Kubernetes clients
	dynamicClient      *dynamic.DynamicClient
	discoveryClient    *discovery.DiscoveryClient
	discoveryInterface discovery.DiscoveryInterface

	reader           Reader
	writer           Writer
	backupResources  map[string]*common.ResourceItems
	restoredItems    map[common.ItemKey]common.RestoredItemStatus
	filter           *filter.GlobalIncludeExclude
	sanitizerFactory func(resource string) sanitizers.Sanitizer
}

func NewResourceManager(opts *common.Options) (*ResourceManager, error) {
	opts.Config.QPS, opts.Config.Burst = 1e6, 1e6
	if err := rest.SetKubernetesDefaults(opts.Config); err != nil {
		return nil, fmt.Errorf("failed to set Kubernetes defaults: %w", err)
	}

	opts.Config.NegotiatedSerializer = serializer.WithoutConversionCodecFactory{CodecFactory: scheme.Codecs}
	if opts.Config.UserAgent == "" {
		opts.Config.UserAgent = rest.DefaultKubernetesUserAgent()
	}
	if opts.RestoreSession != nil {
		opts.StorageClassMappings = parseSCMappings(opts.StorageClassMappingsStr)
		opts.ExcludeResources = append(opts.ExcludeResources, common.DefaultNonRestorableResources...)
	}

	dyn, err := dynamic.NewForConfig(opts.Config)
	if err != nil {
		return nil, fmt.Errorf("creating dynamic client: %w", err)
	}
	disc, err := discovery.NewDiscoveryClientForConfig(opts.Config)
	if err != nil {
		return nil, fmt.Errorf("creating discovery client: %w", err)
	}
	disInt, err := discovery.NewDiscoveryClientForConfig(opts.Config)
	if err != nil {
		return nil, fmt.Errorf("failed to create discovery client: %w", err)
	}

	resFilter := filter.NewIncludeExclude().Includes(opts.IncludeResources...).Excludes(opts.ExcludeResources...)
	nsFilter := filter.NewIncludeExclude().Includes(opts.IncludeNamespaces...).Excludes(opts.ExcludeNamespaces...)
	globalFilter := filter.NewGlobalIncludeExclude(resFilter, nsFilter, opts.IncludeClusterResources)

	klog.Info("ResourceManager initialized")
	return &ResourceManager{
		Options:            opts,
		dynamicClient:      dyn,
		discoveryClient:    disc,
		discoveryInterface: disInt,
		filter:             globalFilter,
		backupResources:    make(map[string]*common.ResourceItems),
		restoredItems:      make(map[common.ItemKey]common.RestoredItemStatus),
		sanitizerFactory: func(resource string) sanitizers.Sanitizer {
			return sanitizers.NewSanitizer(resource)
		},
		reader: NewFileReader(),
		writer: NewFileWriter(),
	}, nil
}

func (m *ResourceManager) DumpManifests(ctx context.Context) error {
	apiLists, err := m.waitForAPIResources(ctx, 3*time.Minute, 5*time.Second)
	if err != nil {
		return fmt.Errorf("discover resources: %w", err)
	}

	for _, apiList := range apiLists {
		gv, err := schema.ParseGroupVersion(apiList.GroupVersion)
		if err != nil {
			klog.Warningf("invalid groupVersion %s: %v", apiList.GroupVersion, err)
			continue
		}
		for _, res := range apiList.APIResources {
			if !validResource(res) {
				continue
			}
			gvr := gv.WithResource(res.Name)
			if !m.filter.ShouldIncludeResource(res.Name, res.Namespaced) {
				continue
			}
			if err := m.listAndStore(ctx, gvr); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *ResourceManager) waitForAPIResources(ctx context.Context, timeout, interval time.Duration) ([]*metav1.APIResourceList, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			lists, err := m.discoveryClient.ServerPreferredResources()
			if err != nil {
				klog.Infof("retry discovery: %v", err)
				continue
			}
			klog.Info("API discovery successful")
			return lists, nil
		}
	}
}

func (m *ResourceManager) listAndStore(ctx context.Context, gvr schema.GroupVersionResource) error {
	list, err := m.dynamicClient.Resource(gvr).Namespace(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		klog.Warningf("list %s: %v", gvr.Resource, err)
		return nil // skip on error
	}
	for _, item := range list.Items {
		if !m.shouldDump(item) {
			continue
		}
		path := m.buildFilePath(gvr.GroupResource().String(), item.GetNamespace(), item.GetName())
		if err := m.storeItem(gvr.Resource, path, item.Object); err != nil {
			return err
		}
	}
	return nil
}

func (m *ResourceManager) shouldDump(item unstructured.Unstructured) bool {
	ns := item.GetNamespace()
	if ns != "" && !m.filter.ShouldIncludeNamespace(ns) {
		klog.V(2).Infof("skip namespace: %s", ns)
		return false
	}
	labels := labelsToStrings(item.GetLabels())
	if !matchesAny(labels, m.ORedLabelSelector) {
		klog.V(3).Info("no OR labels match, skip")
		return false
	}
	if !matchesAll(labels, m.ANDedLabelSelector) {
		klog.V(3).Info("not all AND labels match, skip")
		return false
	}
	return true
}

func (m *ResourceManager) storeItem(resource string, filePath string, obj map[string]interface{}) error {
	if m.Sanitize && (resource != common.Pods.Resource && resource != common.Jobs.Resource) { // Ignoring Pods and Jobs, as we need to restore them based on their status phase and completion time.
		sObj, err := m.sanitizerFactory(resource).Sanitize(obj)
		if err != nil {
			return fmt.Errorf("sanitize %s: %w", resource, err)
		}
		obj = sObj
	}
	data, err := yaml.Marshal(obj)
	if err != nil {
		return fmt.Errorf("marshal YAML: %w", err)
	}
	if err := m.writer.Write(filePath, data); err != nil {
		return fmt.Errorf("write file %s: %w", filePath, err)
	}
	klog.Infof("wrote %s", filePath)
	return nil
}

func (m *ResourceManager) buildFilePath(groupResource, namespace, name string) string {
	scopeDir := common.ClusterScopedDir
	if namespace != "" {
		scopeDir = common.NamespaceScopedDir
	}
	return filepath.Join(m.DataDir, groupResource, scopeDir, namespace, name+".yaml")
}
