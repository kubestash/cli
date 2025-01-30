/*
Copyright AppsCode Inc. and Contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package pkg

import (
	"encoding/json"
	"fmt"
	vsapi "github.com/kubernetes-csi/external-snapshotter/client/v7/apis/volumesnapshot/v1"
	"gomodules.xyz/envsubst"
	core "k8s.io/api/core/v1"
	clientsetscheme "k8s.io/client-go/kubernetes/scheme"
	cu "kmodules.xyz/client-go/client"
	"kubestash.dev/apimachinery/apis"
	addonapi "kubestash.dev/apimachinery/apis/addons/v1alpha1"
	coreapi "kubestash.dev/apimachinery/apis/core/v1alpha1"
	storageapi "kubestash.dev/apimachinery/apis/storage/v1alpha1"
	"os"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func NewUncachedClient() (client.Client, error) {
	cfg, err := ctrl.GetConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get Kubernetes config. Reason: %w", err)
	}

	return cu.NewUncachedClient(
		cfg,
		clientsetscheme.AddToScheme,
		storageapi.AddToScheme,
		coreapi.AddToScheme,
		addonapi.AddToScheme,
		vsapi.AddToScheme,
	)
}

func GetTmpVolumeAndMount() (core.Volume, core.VolumeMount) {
	vol := core.Volume{
		Name: apis.TempDirVolumeName,
		VolumeSource: core.VolumeSource{
			EmptyDir: &core.EmptyDirVolumeSource{},
		},
	}
	mnt := core.VolumeMount{
		Name:      apis.TempDirVolumeName,
		MountPath: apis.TempDirMountPath,
	}

	return vol, mnt
}

func ResolveWithInputs(obj interface{}, inputs map[string]string) error {
	// convert to JSON, apply replacements and convert back to struct
	jsonObj, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	resolved, err := envsubst.EvalMap(string(jsonObj), inputs)
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(resolved), obj)
}

func GetProxyEnvVariables() []core.EnvVar {
	proxyVars := []string{
		"HTTP_PROXY", "http_proxy",
		"HTTPS_PROXY", "https_proxy",
		"NO_PROXY", "no_proxy",
	}
	var envs []core.EnvVar
	for _, env := range proxyVars {
		if v, ok := os.LookupEnv(env); ok {
			envs = append(envs, core.EnvVar{
				Name:  env,
				Value: v,
			})
		}
	}
	return envs
}
