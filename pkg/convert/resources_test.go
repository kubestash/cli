/*
Copyright AppsCode Inc. and Contributors

Licensed under the AppsCode Community License 1.0.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://github.com/appscode/licenses/raw/1.0.0/AppsCode-Community-1.0.0.md

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package convert

import (
	"testing"

	"stash.appscode.dev/apimachinery/apis/stash/v1alpha1"

	core "k8s.io/api/core/v1"
	store "kmodules.xyz/objectstore-api/api/v1"
)

func TestBuildBackupStorageCopiesLocalPersistentVolumeClaim(t *testing.T) {
	backupStorage := buildBackupStorage("local-repository", "demo", v1alpha1.RepositorySpec{
		Backend: store.Backend{
			Local: &store.LocalSpec{
				VolumeSource: core.VolumeSource{
					PersistentVolumeClaim: &core.PersistentVolumeClaimVolumeSource{
						ClaimName: "backup-pvc",
						ReadOnly:  true,
					},
				},
				MountPath: "/stash-backup",
				SubPath:   "postgres",
			},
		},
	})

	local := backupStorage.Spec.Storage.Local
	if local == nil {
		t.Fatal("expected local storage to be configured")
	}
	if local.PersistentVolumeClaim == nil {
		t.Fatal("expected persistentVolumeClaim to be copied")
	}
	if local.PersistentVolumeClaim.ClaimName != "backup-pvc" {
		t.Errorf("claimName = %q, want %q", local.PersistentVolumeClaim.ClaimName, "backup-pvc")
	}
	if !local.PersistentVolumeClaim.ReadOnly {
		t.Error("readOnly = false, want true")
	}
	if local.MountPath != "/stash-backup" {
		t.Errorf("mountPath = %q, want %q", local.MountPath, "/stash-backup")
	}
	if local.SubPath != "postgres" {
		t.Errorf("subPath = %q, want %q", local.SubPath, "postgres")
	}
}
