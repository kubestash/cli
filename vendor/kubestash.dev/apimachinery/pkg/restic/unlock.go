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
	"bytes"
	"context"
	"fmt"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"
	kutil "kmodules.xyz/client-go"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"time"
)

func (w *ResticWrapper) UnlockRepository(repository string) error {
	_, err := w.unlock(repository)
	return err
}

// getLockIDs lists every lock ID currently held in the repository.
func (w *ResticWrapper) getLockIDs(repository string) ([]string, error) {
	w.sh.ShowCMD = true
	out, err := w.listLocks(repository)
	if err != nil {
		return nil, err
	}
	return extractLockIDs(bytes.NewReader(out))
}

// getLockStats returns the decoded JSON for a single lock.
func (w *ResticWrapper) getLockStats(repository, lockID string) (*LockStats, error) {
	w.sh.ShowCMD = true
	out, err := w.lockStats(repository, lockID)
	if err != nil {
		return nil, err
	}
	return extractLockStats(out)
}

// getPodNameIfAnyExclusiveLock scans every lock and returns the hostname aka (Pod name) of the first exclusive lock it finds, or "" if none exist.
func (w *ResticWrapper) getPodNameIfAnyExclusiveLock(repository string) (string, error) {
	klog.Infoln("Checking for exclusive locks in the repository...")
	ids, err := w.getLockIDs(repository)
	if err != nil {
		return "", fmt.Errorf("failed to list locks: %w", err)
	}
	for _, id := range ids {
		st, err := w.getLockStats(repository, id)
		if err != nil {
			return "", fmt.Errorf("failed to inspect lock %s: %w", id, err)
		}
		if st.Exclusive { // There's no chances to get multiple exclusive locks, so we can return the first one we find.
			return st.Hostname, nil
		}
	}
	return "", nil
}

// EnsureNoExclusiveLock blocks until any exclusive lock is released.
// If a lock is held by a Running Pod, it waits; otherwise it unlocks.
func (w *ResticWrapper) EnsureNoExclusiveLock(rClient client.Client, namespace string) error {
	klog.Infoln("Ensuring no exclusive lock is held on any repositories...")

	for _, b := range w.Config.Backends {
		klog.Infof("Checking for exclusive lock on repository: %s", b.Repository)
		podName, err := w.getPodNameIfAnyExclusiveLock(b.Repository)
		if err != nil {
			return fmt.Errorf("failed to check exclusive lock for repository %s: %w", b.Repository, err)
		}
		if podName == "" {
			klog.Infof("No exclusive lock found for repository: %s, proceeding...", b.Repository)
			continue
		}

		klog.Infof("Exclusive lock found, held by Pod: %s for repository: %s. Waiting for it to complete...", podName, b.Repository)
		return wait.PollUntilContextTimeout(
			context.Background(),
			5*time.Second,
			kutil.ReadinessTimeout,
			true,
			func(ctx context.Context) (bool, error) {
				klog.Infof("Checking Pod status: %s...", podName)

				var pod corev1.Pod
				err := rClient.Get(context.Background(), client.ObjectKey{Name: podName, Namespace: namespace}, &pod)
				switch {
				case errors.IsNotFound(err): // Pod gone → unlock
					klog.Infof("Pod %s not found. Assuming it has terminated. Attempting to unlock repository: %s", podName, b.Repository)
					_, unlockErr := w.unlock(b.Repository)
					return true, unlockErr

				case err != nil: // API error → stop
					return false, fmt.Errorf("error fetching Pod %s: %w", podName, err)

				case pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed: // Pod finished → unlock
					klog.Infof("Pod %s finished with phase %s. Attempting to unlock repository: %s", podName, pod.Status.Phase, b.Repository)
					_, unlockErr := w.unlock(b.Repository)
					return true, unlockErr

				default: // Not finished yet → keep waiting
					klog.Infof("Pod %s is still running with phase %s. Waiting...", podName, pod.Status.Phase)
					return false, nil
				}
			},
		)
	}

	klog.Infoln("All repositories are free of exclusive locks.")
	return nil
}
