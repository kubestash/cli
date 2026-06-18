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

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/klog/v2"
)

const FileModeRWXAll = 0o777

type BackupOutput struct {
	// Stats shows statistics of individual hosts
	Stats []HostBackupStats `json:"stats,omitempty"`
}

type RestoreOutput struct {
	// Stats shows restore statistics of individual hosts
	Stats []HostRestoreStats `json:"stats,omitempty"`
}

type RepositoryStats struct {
	// Integrity shows result of repository integrity check after last backup
	Integrity *bool `json:"integrity,omitempty"`
	// Size show size of repository after last backup
	Size string `json:"size,omitempty"`
	// SnapshotCount shows number of snapshots stored in the repository
	SnapshotCount int64 `json:"snapshotCount,omitempty"`
	// SnapshotsRemovedOnLastCleanup shows number of old snapshots cleaned up according to retention policy on last backup session
	SnapshotsRemovedOnLastCleanup int64 `json:"snapshotsRemovedOnLastCleanup,omitempty"`
}

// ExtractBackupInfo extract information from output of "restic backup" command and
// save valuable information into backupOutput
func extractBackupInfo(output []byte, path string) ([]SnapshotStats, error) {
	// unmarshal json output
	var jsonOutputs []BackupSummary
	dec := json.NewDecoder(bytes.NewReader(output))
	var errs []error
	for {
		var summary BackupSummary
		if err := dec.Decode(&summary); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			errs = append(errs, fmt.Errorf("error decoding JSON: %w", err))
		}
		if summary.MessageType != "summary" {
			continue
		}
		jsonOutputs = append(jsonOutputs, summary)
	}
	if len(errs) > 0 {
		return nil, utilerrors.NewAggregate(errs)
	}
	var snapshotStatsList []SnapshotStats
	for _, jsonOutput := range jsonOutputs {
		snapshotStats := SnapshotStats{
			Path: path,
		}
		snapshotStats.FileStats.NewFiles = jsonOutput.FilesNew
		snapshotStats.FileStats.ModifiedFiles = jsonOutput.FilesChanged
		snapshotStats.FileStats.UnmodifiedFiles = jsonOutput.FilesUnmodified
		snapshotStats.FileStats.TotalFiles = jsonOutput.TotalFilesProcessed

		snapshotStats.Uploaded = formatBytes(jsonOutput.DataAdded)
		snapshotStats.TotalSize = formatBytes(jsonOutput.TotalBytesProcessed)
		snapshotStats.ProcessingTime = formatSeconds(uint64(jsonOutput.TotalDuration))
		snapshotStats.Name = jsonOutput.SnapshotID
		snapshotStatsList = append(snapshotStatsList, snapshotStats)
	}

	return snapshotStatsList, nil
}

// ExtractCheckInfo extract information from output of "restic check" command and
// save valuable information into backupOutput
func extractCheckInfo(out []byte) bool {
	scanner := bufio.NewScanner(bytes.NewReader(out))
	var line string
	for scanner.Scan() {
		line = scanner.Text()
		line = strings.TrimSpace(line)
		if line == "no errors were found" {
			return true
		}
	}
	return false
}

// ExtractStatsInfo extract information from output of "restic stats" command and
// save valuable information into backupOutput
func extractStatsInfo(out []byte) (string, error) {
	var stat StatsContainer
	err := json.Unmarshal(out, &stat)
	if err != nil {
		return "", err
	}
	return formatBytes(stat.TotalSize), nil
}

type BackupSummary struct {
	MessageType         string  `json:"message_type"` // "summary"
	FilesNew            *int64  `json:"files_new"`
	FilesChanged        *int64  `json:"files_changed"`
	FilesUnmodified     *int64  `json:"files_unmodified"`
	DataAdded           uint64  `json:"data_added"`
	TotalFilesProcessed *int64  `json:"total_files_processed"`
	TotalBytesProcessed uint64  `json:"total_bytes_processed"`
	TotalDuration       float64 `json:"total_duration"` // in seconds
	SnapshotID          string  `json:"snapshot_id"`
}

type ResticStatus struct {
	MessageType      string   `json:"message_type"`
	SecondsElapsed   int64    `json:"seconds_elapsed"`
	SecondsRemaining int64    `json:"seconds_remaining"`
	PercentDone      float64  `json:"percent_done"`
	TotalFiles       int      `json:"total_files"`
	TotalBytes       uint64   `json:"total_bytes"`
	BytesRestored    uint64   `json:"bytes_restored"`
	BytesDone        int64    `json:"bytes_done"`
	CurrentFiles     []string `json:"current_files"`
}

type ForgetGroup struct {
	Keep   []json.RawMessage `json:"keep"`
	Remove []json.RawMessage `json:"remove"`
}

type StatsContainer struct {
	TotalSize uint64 `json:"total_size"`
}

type LockStats struct {
	Time      time.Time `json:"time"`
	Exclusive bool      `json:"exclusive"` // true if the lock is exclusive, false if it is non-exclusive
	Hostname  string    `json:"hostname"`  // Hostname of the machine where the lock was created, our case PodName
	Username  string    `json:"username"`
	PID       int       `json:"pid"`
	UID       int       `json:"uid"`
	GID       int       `json:"gid"`
}

func extractLockStats(raw []byte) (*LockStats, error) {
	var stats LockStats
	if err := json.Unmarshal(raw, &stats); err != nil {
		return nil, fmt.Errorf("cannot decode lock JSON: %w", err)
	}
	return &stats, nil
}

func extractLockIDs(r io.Reader) ([]string, error) {
	sc := bufio.NewScanner(r)
	var ids []string

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if len(line) >= 64 {
			ids = append(ids, line[:64])
		}
	}
	return ids, sc.Err()
}

func extractStatus(output []byte) []ResticStatus {
	data := sanitizeFromStart(output)
	if data == nil {
		klog.Infoln("status cannot be sanitized from start, data is not valid, ignoring it...")
		return nil
	}

	data = sanitizeFromEnd(data)
	if data == nil {
		klog.Infoln("status cannot be sanitized from end, data is not valid, ignoring it...")
		return nil
	}
	var results []ResticStatus
	decoder := json.NewDecoder(bytes.NewReader(data))
	for {
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			klog.Infoln("cannot decode status JSON", "error", err)
			continue
		}
		var s ResticStatus
		if err := json.Unmarshal(raw, &s); err != nil {
			klog.Infoln("cannot decode status JSON", "error", err)
			continue
		}
		results = append(results, s)
	}
	return results
}

func statusSince(output []byte, since int) (int, []ResticStatus) {
	start := since
	if start < 0 {
		start = 0
	}
	if start > len(output) {
		start = len(output)
	}

	data := output[start:]
	if len(data) == 0 {
		return start, nil
	}

	end := bytes.LastIndexByte(data, '}')
	if end == -1 {
		return start, nil
	}

	cursor := start + end + 1
	return cursor, extractStatus(data[:end+1])
}

func sanitizeFromStart(data []byte) []byte {
	start := bytes.IndexByte(data, '{')
	if start == -1 {
		return nil
	}
	return data[start:]
}

func sanitizeFromEnd(data []byte) []byte {
	end := bytes.LastIndexByte(data, '}')
	if end == -1 {
		return nil
	}
	return data[:end+1]
}
