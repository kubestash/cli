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
	"os"

	"kubestash.dev/apimachinery/apis/config/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

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

var (
	klient client.Client

	dstNamespace string
	srcNamespace string

	backupConfigName string

	imgRestic v1alpha1.Docker
)

func init() {
	imgRestic.Registry = ResticRegistry
	imgRestic.Image = ResticImage
	imgRestic.Tag = ResticTag
}

type cliLocalDirectories struct {
	configDir    string // temp dir
	downloadDir  string // user provided or, current working dir
	componentDir string
}

func (localDirs *cliLocalDirectories) prepareDownloadDir() (err error) {
	// if destination flag is not specified, restore in current directory
	if localDirs.downloadDir == "" {
		if localDirs.downloadDir, err = os.Getwd(); err != nil {
			return err
		}
	}
	return os.MkdirAll(localDirs.downloadDir, 0o755)
}
