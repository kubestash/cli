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

package file

import (
	"os"
	"path/filepath"
)

type Writer interface {
	Write(string, []byte) error
}

type Reader interface {
	ReadFile(string) ([]byte, error)
	ReadDir(string) ([]os.FileInfo, error)
}
type (
	fileWriter struct{}
	fileReader struct{}
)

func NewFileWriter() Writer {
	return fileWriter{}
}

func NewFileReader() Reader {
	return fileReader{}
}

func (w fileWriter) Write(path string, data []byte) error {
	dir := filepath.Dir(path)
	err := os.MkdirAll(dir, 0o777)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0o644)
}

func (f fileReader) ReadDir(dirname string) ([]os.FileInfo, error) {
	var fileInfos []os.FileInfo
	dirInfos, ise := os.ReadDir(dirname)
	if ise != nil {
		return fileInfos, ise
	}
	for _, dirInfo := range dirInfos {
		fileInfo, ise := dirInfo.Info()
		if ise == nil {
			fileInfos = append(fileInfos, fileInfo)
		}
	}
	return fileInfos, nil
}

func (f fileReader) ReadFile(fileName string) ([]byte, error) {
	return os.ReadFile(fileName)
}
