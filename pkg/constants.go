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

import "time"

// These variables will be set during build time
const (
	ScratchDir     = "/tmp/scratch"
	DestinationDir = "/tmp/destination"
	configDirName  = "config"

	ResticEnvs     = "restic-envs"
	ResticRegistry = "restic"
	ResticImage    = "restic"
	ResticTag      = "0.15.1"
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
	PVCBackupTask  = "pvc-backup"
	PVCRestoreTask = "pvc-restore"
	PVCSession     = "pvc-session"
	PVCSchedule    = "*/59 * * * *"
	LatestSnapshot = "latest"
)

const (
	CmdKubectl = "kubectl"
)
