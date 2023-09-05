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

	vsapi "github.com/kubernetes-csi/external-snapshotter/client/v4/apis/volumesnapshot/v1"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
	kmc "kmodules.xyz/client-go/client"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func NewCmdCopyVolumeSnapshot() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "volumesnapshot",
		Short:             `Copy VolumeSnapshot`,
		Long:              `Copy VolumeSnapshot from one namespace to another namespace`,
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			volumeSnapshotName := args[0]

			volumeSnapshot, err := getVolumeSnapshot(volumeSnapshotName)
			if err != nil {
				return err
			}

			klog.Infof("Copying VolumeSnapshot %s to %s namespace", volumeSnapshot.Namespace, dstNamespace)
			return createVolumeSnapshot(volumeSnapshot)
		},
	}

	return cmd
}

func getVolumeSnapshot(name string) (*vsapi.VolumeSnapshot, error) {
	volumeSnapshot := &vsapi.VolumeSnapshot{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: srcNamespace,
		},
	}
	if err := klient.Get(context.Background(), client.ObjectKeyFromObject(volumeSnapshot), volumeSnapshot); err != nil {
		return nil, err
	}

	return volumeSnapshot, nil
}

func createVolumeSnapshot(vs *vsapi.VolumeSnapshot) error {
	newVS := &vsapi.VolumeSnapshot{
		ObjectMeta: metav1.ObjectMeta{
			Name:        vs.Name,
			Namespace:   dstNamespace,
			Labels:      vs.Labels,
			Annotations: vs.Annotations,
		},
	}
	_, err := kmc.CreateOrPatch(
		context.Background(),
		klient,
		newVS,
		func(obj client.Object, createOp bool) client.Object {
			in := obj.(*vsapi.VolumeSnapshot)
			in.Spec = newVS.Spec
			return in
		},
	)
	if err != nil {
		return err
	}

	klog.Infof("VolumeSnapshot %s/%s has been copied to %s namespace successfully.", vs.Namespace, vs.Name, dstNamespace)
	return nil
}
