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

	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	"kubestash.dev/apimachinery/apis"
	"kubestash.dev/apimachinery/pkg/resourceops/filter"
	"kubestash.dev/apimachinery/pkg/resourceops/sanitizers"
	"kubestash.dev/cli/pkg/common"
)

type ResourceManager struct {
	*common.Options

	// Kubernetes clients
	dynamicClient   *dynamic.DynamicClient
	discoveryClient *discovery.DiscoveryClient

	reader          Reader
	writer          Writer
	backupResources map[string]*common.ResourceItems
	restoredItems   map[common.ItemKey]common.RestoredItemStatus

	maxIterations    uint
	currentIteration uint

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
		opts.ExcludeResources = append(opts.ExcludeResources, apis.DefaultNonRestorableResources...)
	}

	dyn, err := dynamic.NewForConfig(opts.Config)
	if err != nil {
		return nil, fmt.Errorf("creating dynamic client: %w", err)
	}
	disc, err := discovery.NewDiscoveryClientForConfig(opts.Config)
	if err != nil {
		return nil, fmt.Errorf("creating discovery client: %w", err)
	}

	opts.IncludeNamespaces = TrimSpaceFromList(opts.IncludeNamespaces)
	opts.ExcludeNamespaces = TrimSpaceFromList(opts.ExcludeNamespaces)
	opts.IncludeResources = TrimSpaceFromList(opts.IncludeResources)
	opts.ExcludeResources = TrimSpaceFromList(opts.ExcludeResources)
	opts.ANDedLabelSelectors = TrimSpaceFromList(opts.ANDedLabelSelectors)
	opts.ORedLabelSelectors = TrimSpaceFromList(opts.ORedLabelSelectors)

	resFilter := filter.NewIncludeExclude().Includes(opts.IncludeResources...).Excludes(opts.ExcludeResources...)
	nsFilter := filter.NewIncludeExclude().Includes(opts.IncludeNamespaces...).Excludes(opts.ExcludeNamespaces...)
	globalFilter := filter.NewGlobalIncludeExclude(resFilter, nsFilter, opts.IncludeClusterResources)

	klog.Info("ResourceManager initialized")
	return &ResourceManager{
		Options:         opts,
		dynamicClient:   dyn,
		discoveryClient: disc,
		filter:          globalFilter,
		backupResources: make(map[string]*common.ResourceItems),
		restoredItems:   make(map[common.ItemKey]common.RestoredItemStatus),

		maxIterations:    uint(5),
		currentIteration: uint(1),

		sanitizerFactory: func(resource string) sanitizers.Sanitizer {
			return sanitizers.NewSanitizer(resource)
		},
		reader: NewFileReader(),
		writer: NewFileWriter(),
	}, nil
}
