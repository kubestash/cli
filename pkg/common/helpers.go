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

package common

import (
	"context"
	"os"

	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/rest"
	restclient "k8s.io/client-go/rest"
	kmapi "kmodules.xyz/client-go/api/v1"
	kubedbapi "kubedb.dev/apimachinery/apis/kubedb/v1alpha2"
	coreapi "kubestash.dev/apimachinery/apis/core/v1alpha1"
	storageapi "kubestash.dev/apimachinery/apis/storage/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
)

func NewRuntimeClient(cfg *restclient.Config) (client.Client, error) {
	scheme := runtime.NewScheme() // for encoding, decoding, converting api objects across different versions
	utilruntime.Must(coreapi.AddToScheme(scheme))
	utilruntime.Must(storageapi.AddToScheme(scheme))
	utilruntime.Must(kubedbapi.AddToScheme(scheme))
	utilruntime.Must(core.AddToScheme(scheme))

	hc, err := rest.HTTPClientFor(cfg)
	if err != nil {
		return nil, err
	}
	mapper, err := apiutil.NewDynamicRESTMapper(cfg, hc)
	if err != nil {
		return nil, err
	}

	return client.New(cfg, client.Options{
		Scheme: scheme,
		Mapper: mapper,
	})
}

func (opt *Options) GetSnapshot(ref kmapi.ObjectReference) (*storageapi.Snapshot, error) {
	snap := &storageapi.Snapshot{}
	if err := opt.Client.Get(context.Background(), ref.ObjectKey(), snap); err != nil {
		return nil, err
	}
	return snap, nil
}

func ClearDir(dir string) error {
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	return os.MkdirAll(dir, os.ModePerm)
}
