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

package restic

import "encoding/json"

func (w *ResticWrapper) ListSnapshots(repository string, snapshotIDs []string) ([]Snapshot, error) {
	return w.listSnapshots(repository, snapshotIDs)
}

func (w *ResticWrapper) DeleteSnapshots(repository string, snapshotIDs []string) ([]byte, error) {
	return w.deleteSnapshots(repository, snapshotIDs)
}

// GetSnapshotSize returns size of a snapshot in bytes
func (w *ResticWrapper) GetSnapshotSize(repository string, snapshotID string) (uint64, error) {
	out, err := w.stats(repository, snapshotID)
	if err != nil {
		return 0, err
	}

	var stat StatsContainer
	err = json.Unmarshal(out, &stat)
	if err != nil {
		return 0, err
	}
	return stat.TotalSize, nil
}

func (w *ResticWrapper) DownloadSnapshot(repository string, options RestoreOptions) error {
	return w.runRestore(repository, options)
}
