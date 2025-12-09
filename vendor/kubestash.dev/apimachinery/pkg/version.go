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

package pkg

import (
	"fmt"
	"regexp"
	"sort"

	"github.com/Masterminds/semver/v3"
)

func extractDBVersion(version string) string {
	regex := `\b\d+\.\d+(\.\d+)?\b`
	r := regexp.MustCompile(regex)
	return r.FindString(version)
}

// {dbVersion, funcName} -> addonVersion
var hardCodedMap = map[struct{ dbVersionRegex, funcNameRegex string }]string{
	{"7.0.*", "mongodb-(backup|restore)"}:        "6.0.5",
	{"5.7.*", "mysql-physical-(backup|restore)"}: "2.4.29",
	// MariaDB Physical Backup|Restore
	{"10.4.*", "mariadb-physical-(backup|restore)"}:  "10.4.32-focal",
	{"10.5.*", "mariadb-physical-(backup|restore)"}:  "10.6.16-focal",
	{"10.6.*", "mariadb-physical-(backup|restore)"}:  "10.6.16-focal",
	{"10.10.*", "mariadb-physical-(backup|restore)"}: "10.11.6-jammy",
	{"10.11.*", "mariadb-physical-(backup|restore)"}: "10.11.6-jammy",
	{"11.*.*", "mariadb-physical-(backup|restore)"}:  "11.1.3-jammy",
}

func foundInHardCodedMap(funcName, dbVersion string) (bool, string) {
	regexMatched := func(rx, val string) bool {
		r := regexp.MustCompile(rx)
		return r.MatchString(val)
	}
	for key, av := range hardCodedMap {
		if regexMatched(key.funcNameRegex, funcName) && regexMatched(key.dbVersionRegex, dbVersion) {
			return true, av
		}
	}
	return false, ""
}

// For algorithm design & real addon mapping : https://github.com/kubestash/project/issues/140

func FindAppropriateAddonVersion(addonVersions []string, dbVersion, funcName string) (string, error) {
	if len(addonVersions) == 0 {
		return "", fmt.Errorf("available list of addon-versions can't be empty")
	}
	dbVersion = extractDBVersion(dbVersion)
	if found, av := foundInHardCodedMap(funcName, dbVersion); found {
		return av, nil
	}
	semverDBVersion, err := semver.NewVersion(dbVersion)
	if err != nil {
		return "", err
	}

	type distance struct {
		major, minor, patch uint64
		isDB                int
		actualAddon         string
	}
	distances := make([]distance, 0)
	for _, av := range addonVersions {
		tav := extractDBVersion(av)
		sav, err := semver.NewVersion(tav)
		if err != nil {
			return "", err
		}

		distances = append(distances, distance{
			major:       sav.Major(),
			minor:       sav.Minor(),
			patch:       sav.Patch(),
			actualAddon: av,
		})
	}
	if len(distances) == 0 {
		return "", fmt.Errorf("no addon version found with major=%v for db version %s", semverDBVersion.Major(), dbVersion)
	}
	distances = append(distances, distance{
		major: semverDBVersion.Major(),
		minor: semverDBVersion.Minor(),
		patch: semverDBVersion.Patch(),
		isDB:  1,
	})
	sort.Slice(distances, func(i, j int) bool {
		if distances[i].major != distances[j].major {
			return distances[i].major < distances[j].major
		}
		if distances[i].minor != distances[j].minor {
			return distances[i].minor < distances[j].minor
		}
		if distances[i].patch != distances[j].patch {
			return distances[i].patch < distances[j].patch
		}
		return distances[i].isDB < distances[j].isDB
	})

	// klog.Infof("distances: %v", distances)

	// Algorithm:
	// - first sort the versions according to Ascending order of major,minor and patch version
	// - iterate through the distances slide(hold the version information) and if the current version is our DB version,
	//		- if, current.major==immediate_smaller.major, take immediate_smaller if possible or immediate_greater
	//		- else, take immediate_greater if possible or immediate_smaller
	for i, d := range distances {
		if d.isDB == 1 {
			if i > 0 {
				if d.major != distances[i-1].major && i+1 < len(distances) {
					return distances[i+1].actualAddon, nil
				}
				return distances[i-1].actualAddon, nil
			}
			return distances[i+1].actualAddon, nil
		}
	}
	return "", fmt.Errorf("no addon version found for db version %s", dbVersion)
}
