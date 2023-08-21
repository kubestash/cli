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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	cfg "sigs.k8s.io/controller-runtime/pkg/config/v1alpha1"
)

//+kubebuilder:object:root=true

// KubeStashConfig is the Schema for the kubestashconfigs API
type KubeStashConfig struct {
	metav1.TypeMeta `json:",inline"`

	// ControllerManagerConfigurationSpec returns the contfigurations for controllers
	cfg.ControllerManagerConfigurationSpec `json:",inline"`

	// Configuration options related to license
	License LicenseOptions `json:"license,omitempty"`

	// WebhookInfo specifies validating and mutating webhook information
	WebhookInfo WebhookInfo `json:"webhookInfo,omitempty"`

	// Docker specifies the operator's  docker registry, image, and tag information
	Docker Docker `json:"docker,omitempty"`
}

type LicenseOptions struct {
	// Path specifies the path of the license file
	Path string `json:"path,omitempty"`

	// ApiService specifies the name of the ApiService to use by the addons to identify the respective service and certificate for license verification request
	ApiService string `json:"apiService,omitempty"`
}

type WebhookInfo struct {
	Validating GenericWebhookInfo `json:"validating,omitempty"`
	Mutating   GenericWebhookInfo `json:"mutating,omitempty"`
}

type GenericWebhookInfo struct {
	// Enable specifies whether the webhook is enabled or not
	Enable bool `json:"enable,omitempty"`

	// Name specifies the name of the respective webhook
	Name string `json:"name,omitempty"`
}

type Docker struct {
	// Registry specifies the name of a Docker registry
	Registry string `json:"registry,omitempty"`

	// Image specifies the name of a Docker image
	Image string `json:"image,omitempty"`

	// Tag specifies the Docker image tag
	Tag string `json:"tag,omitempty"`
}

func (docker Docker) ToContainerImage() string {
	return docker.Registry + "/" + docker.Image + ":" + docker.Tag
}

func init() {
	SchemeBuilder.Register(&KubeStashConfig{})
}
