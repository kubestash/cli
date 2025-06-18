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
	"fmt"

	kmc "kmodules.xyz/client-go/client"
	"kubestash.dev/apimachinery/apis"
	coreapi "kubestash.dev/apimachinery/apis/core/v1alpha1"
	storageapi "kubestash.dev/apimachinery/apis/storage/v1alpha1"
	"kubestash.dev/apimachinery/pkg/restic"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (opt *Options) InitSnapshotComponentStatus() error {
	for idx := range opt.Snapshots {
		if opt.Snapshots[idx].Status.Components == nil {
			opt.Snapshots[idx].Status.Components = make(map[string]storageapi.Component)
		}
		opt.Snapshots[idx].Status.Components[apis.ComponentManifest] = storageapi.Component{
			Phase: storageapi.ComponentPhaseRunning,
		}

		if err := opt.UpdateSnapshotStatus(&opt.Snapshots[idx]); err != nil {
			return fmt.Errorf("failed to update snapshot status :%w", err)
		}
	}
	return nil
}

func (opt *Options) UpdateSnapshotStatus(snap *storageapi.Snapshot) error {
	_, err := kmc.PatchStatus(
		context.Background(),
		opt.Client,
		snap,
		func(obj client.Object) client.Object {
			in := obj.(*storageapi.Snapshot)
			if in.Status.Components == nil {
				in.Status.Components = make(map[string]storageapi.Component)
			}
			in.Status.TotalComponents = snap.Status.TotalComponents
			in.Status.Components = snap.Status.Components
			return in
		})
	return err
}

func (opt *Options) UpsertRestoreComponentStatus(restoreOutput *restic.RestoreOutput, err error) {
	// If RestoreSession or its Status or Components map is nil, skip updating status safely
	if opt.RestoreSession == nil || opt.RestoreSession.Status.Components == nil {
		return
	}

	newComp := coreapi.ComponentRestoreStatus{}

	if err == nil {
		newComp.Phase = coreapi.RestoreSucceeded
	} else {
		newComp.Phase = coreapi.RestoreFailed
		newComp.Error = err.Error()
	}

	if restoreOutput != nil && len(restoreOutput.Stats) > 0 {
		newComp.Duration = restoreOutput.Stats[0].Duration
	}

	opt.RestoreSession.Status.Components[apis.ComponentManifest] = newComp
}

func UpsertSnapshotsComponentStatus(snapshots []storageapi.Snapshot, backupOutput *restic.BackupOutput, repoStats *restic.RepositoryStats, err error) {
	for idx := range snapshots {
		newComp := storageapi.Component{
			Driver: apis.DriverRestic,
		}

		if err == nil {
			newComp.Phase = storageapi.ComponentPhaseSucceeded
		} else {
			newComp.Phase = storageapi.ComponentPhaseFailed
			newComp.Error = err.Error()
		}

		if backupOutput != nil {
			newComp.Duration = backupOutput.Stats[0].Duration
			var resticStats []storageapi.ResticStats
			for _, snapshot := range backupOutput.Stats[0].Snapshots {
				resticStat := storageapi.ResticStats{
					Id:       snapshot.Name,
					HostPath: snapshot.Path,
					Uploaded: snapshot.Uploaded,
					Size:     snapshot.TotalSize,
				}
				resticStats = append(resticStats, resticStat)
			}
			newComp.ResticStats = resticStats
			newComp.Path = snapshots[idx].GetComponentPath(apis.ComponentManifest)
		}

		if repoStats != nil {
			newComp.Size = repoStats.Size
			newComp.Integrity = repoStats.Integrity
		}

		snapshots[idx].Status.Components[apis.ComponentManifest] = newComp
	}
}

func (opt *Options) SetBackupOutput(w *restic.ResticWrapper, backupOutput []restic.BackupOutput, err error) {
	for idx, backend := range w.Config.Backends {
		for _, snap := range opt.Snapshots {
			if snap.Spec.Repository == backend.Repository {
				var output *restic.BackupOutput
				var repoStats *restic.RepositoryStats
				if err == nil {
					repoStats, err = w.VerifyRepositoryIntegrity(backend.Repository)
					output = &backupOutput[idx]
				}
				UpsertSnapshotsComponentStatus([]storageapi.Snapshot{snap}, output, repoStats, err)
			}
		}
	}
}
