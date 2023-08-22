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

package pkg

import (
	"context"

	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	restclient "k8s.io/client-go/rest"
	kmc "kmodules.xyz/client-go/client"
	configapi "kubestash.dev/apimachinery/apis/config/v1alpha1"
	coreapi "kubestash.dev/apimachinery/apis/core/v1alpha1"
	storageapi "kubestash.dev/apimachinery/apis/storage/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
)

var (
	klient client.Client

	dstNamespace string
	srcNamespace string

	imgRestic configapi.Docker
)

func init() {
	imgRestic.Registry = ResticRegistry
	imgRestic.Image = ResticImage
	imgRestic.Tag = ResticTag
}

func newRuntimeClient(config *restclient.Config) (client.Client, error) {
	scheme := runtime.NewScheme()
	utilruntime.Must(coreapi.AddToScheme(scheme))
	utilruntime.Must(storageapi.AddToScheme(scheme))
	utilruntime.Must(core.AddToScheme(scheme))

	mapper, err := apiutil.NewDynamicRESTMapper(config)
	if err != nil {
		return nil, err
	}

	return client.New(config, client.Options{
		Scheme: scheme,
		Mapper: mapper,
		Opts: client.WarningHandlerOptions{
			SuppressWarnings:   false,
			AllowDuplicateLogs: false,
		},
	})
}

func setBackupConfigurationPausedField(value bool, name string) error {
	backupConfig := &coreapi.BackupConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: srcNamespace,
		},
	}
	if err := klient.Get(context.Background(), client.ObjectKeyFromObject(backupConfig), backupConfig); err != nil {
		return err
	}

	_, err := kmc.CreateOrPatch(
		context.Background(),
		klient,
		backupConfig,
		func(obj client.Object, createOp bool) client.Object {
			in := obj.(*coreapi.BackupConfiguration)
			in.Spec.Paused = value
			return in
		},
	)
	return err
}
