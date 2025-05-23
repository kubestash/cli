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

package pkg

import "time"

// These variables will be set during build time
const (
	CmdKubectl = "kubectl"
	CmdDocker  = "docker"

	ScratchDir          = "/tmp/scratch"
	DestinationDir      = "/tmp/destination"
	SnapshotDownloadDir = "/kubestash-tmp/snapshot"
	PasswordFile        = "/kubestash-tmp/password.txt"
	ConfigDir           = "/tmp/scratch/config"

	ResticEnvs     = "restic-envs"
	ResticRegistry = "restic"
	ResticImage    = "restic"
	ResticTag      = "latest"
	EnvHttpProxy   = "HTTP_PROXY"
	EnvHttpsProxy  = "HTTPS_PROXY"
)

// Constants for debugging
const (
	Condition       = "Conditions"
	Snapshot        = "Snapshots"
	Session         = "Sessions"
	Component       = "Components"
	RetentionPolicy = "RetentionPolicies"
	Target          = "Target"
	Backend         = "Backends"
)

const (
	PullInterval = time.Second * 2
	WaitTimeOut  = time.Minute * 10
)

// Constants for PVC cloning
const (
	PVCAddon       = "pvc-addon"
	PVCBackupTask  = "logical-backup"
	PVCRestoreTask = "logical-backup-restore"
	PVCSchedule    = "*/59 * * * *"
	LatestSnapshot = "latest"
)
