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

import (
	"context"
	"fmt"
	"os"
	"slices"

	"github.com/spf13/cobra"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kmapi "kmodules.xyz/client-go/api/v1"
	core_util "kmodules.xyz/client-go/core/v1"
	meta_util "kmodules.xyz/client-go/meta"
	"kubestash.dev/apimachinery/apis"
	coreapi "kubestash.dev/apimachinery/apis/core/v1alpha1"
	storageapi "kubestash.dev/apimachinery/apis/storage/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type backupDebugOptions struct {
	backupConfig  *coreapi.BackupConfiguration
	backupSession coreapi.BackupSession
	sessions      []string
}

func NewCmdDebugBackup() *cobra.Command {
	var latest bool
	debugOpt := backupDebugOptions{}
	cmd := &cobra.Command{
		Use:               "backup",
		Short:             `Debug backup`,
		Long:              `Debug common KubeStash backup issues`,
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			debugOpt.backupConfig, err = getBackupConfiguration(kmapi.ObjectReference{
				Name:      args[0],
				Namespace: srcNamespace,
			})
			if err != nil {
				return err
			}

			if debugOpt.backupConfig.Status.Phase == coreapi.BackupInvokerInvalid {
				return debugOpt.showTableForInvalidBackupConfig()
			}

			if debugOpt.backupConfig.Status.Phase == coreapi.BackupInvokerNotReady {
				return debugOpt.showTableForNotReadyBackupConfig()
			}

			backupSessions, err := debugOpt.getOwnedFailedBackupSessions()
			if err != nil {
				return err
			}

			if latest {
				if err = debugOpt.debugLatestBackupSessions(backupSessions); err != nil {
					return err
				}
				return nil
			}

			for _, bs := range backupSessions {
				if !slices.Contains(debugOpt.sessions, bs.Spec.Session) {
					continue
				}
				debugOpt.backupSession = bs
				if err = debugOpt.showTableForFailedBackupSession(); err != nil {
					return err
				}
			}

			return nil
		},
	}
	cmd.Flags().StringSliceVar(&debugOpt.sessions, "sessions", debugOpt.sessions, "List of sessions to debug")
	cmd.Flags().BoolVar(&latest, "latest", false, "Debug only latest BackupSessions")

	return cmd
}

func (opt *backupDebugOptions) showTableForInvalidBackupConfig() error {
	var data [][]string
	for _, cond := range opt.backupConfig.Status.Conditions {
		if cond.Type == coreapi.TypeValidationPassed &&
			cond.Status == metav1.ConditionFalse {
			data = append(data, []string{Condition, cond.Message})
		}
	}

	_, err := fmt.Fprintf(os.Stdout, "Debugging BackupConfiguration: %s/%s\n", opt.backupConfig.Namespace, opt.backupConfig.Name)
	if err != nil {
		return err
	}

	return createTable(data)
}

func (opt *backupDebugOptions) showTableForNotReadyBackupConfig() error {
	var data [][]string
	// check target existence
	if opt.backupConfig.Status.TargetFound == nil || !*opt.backupConfig.Status.TargetFound {
		data = append(data, []string{Target, fmt.Sprintf("%s/%s not found", opt.backupConfig.Spec.Target.Namespace, opt.backupConfig.Spec.Target.Name)})
	}

	// check if backend ready
	if len(opt.backupConfig.Status.Backends) != len(opt.backupConfig.Spec.Backends) {
		data = append(data, []string{Backend, "one or more backends are not ready"})
	}

	for _, backend := range opt.backupConfig.Status.Backends {
		if !*backend.Ready {
			data = append(data, []string{Backend, fmt.Sprintf("%s not ready", backend.Name)})
		}
	}

	// check if session ready
	if len(opt.backupConfig.Spec.Sessions) != len(opt.backupConfig.Status.Sessions) {
		data = append(data, []string{Session, "one or more sessions are not ready"})
	}

	for _, status := range opt.backupConfig.Status.Sessions {
		for _, cond := range status.Conditions {
			if cond.Type == coreapi.TypeSchedulerEnsured &&
				cond.Status == metav1.ConditionFalse {
				data = append(data, []string{Session, cond.Message})
			}
		}
	}

	_, err := fmt.Fprintf(os.Stdout, "Debugging BackupConfiguration: %s/%s\n", opt.backupConfig.Namespace, opt.backupConfig.Name)
	if err != nil {
		return err
	}

	return createTable(data)
}

func (opt *backupDebugOptions) getOwnedFailedBackupSessions() ([]coreapi.BackupSession, error) {
	var bsList coreapi.BackupSessionList
	opts := []client.ListOption{client.InNamespace(srcNamespace)}
	if err := klient.List(context.Background(), &bsList, opts...); err != nil {
		return nil, err
	}

	var ownedFailedBackupSessions []coreapi.BackupSession
	for i := range bsList.Items {
		if owned, _ := core_util.IsOwnedBy(&bsList.Items[i], opt.backupConfig); owned &&
			bsList.Items[i].Status.Phase == coreapi.BackupSessionFailed {
			ownedFailedBackupSessions = append(ownedFailedBackupSessions, bsList.Items[i])
		}
	}
	return ownedFailedBackupSessions, nil
}

func (opt *backupDebugOptions) debugLatestBackupSessions(backupSessions []coreapi.BackupSession) error {
	if len(opt.sessions) == 0 {
		for _, session := range opt.backupConfig.Spec.Sessions {
			opt.backupSession = opt.getLatestBackupSession(session.Name, backupSessions)
			if err := opt.showTableForFailedBackupSession(); err != nil {
				return err
			}
		}
		return nil
	}

	for _, session := range opt.sessions {
		opt.backupSession = opt.getLatestBackupSession(session, backupSessions)
		if err := opt.showTableForFailedBackupSession(); err != nil {
			return err
		}
	}
	return nil
}

func (opt *backupDebugOptions) getLatestBackupSession(session string, backupSessions []coreapi.BackupSession) coreapi.BackupSession {
	var bs coreapi.BackupSession
	var tm *metav1.Time
	for _, backupSession := range backupSessions {
		if backupSession.Spec.Session != session {
			continue
		}

		if tm == nil {
			tm = &metav1.Time{Time: backupSession.CreationTimestamp.Time}
			bs = backupSession
		} else if tm.Before(&metav1.Time{Time: backupSession.CreationTimestamp.Time}) {
			tm = &metav1.Time{Time: backupSession.CreationTimestamp.Time}
			bs = backupSession
		}
	}
	return bs
}

func (opt *backupDebugOptions) showTableForFailedBackupSession() error {
	var data [][]string

	for _, cond := range opt.backupSession.Status.Conditions {
		if cond.Status == metav1.ConditionFalse {
			data = append(data, []string{Condition, cond.Message})
		}
	}

	var failedSnapStatus []coreapi.SnapshotStatus
	for _, snap := range opt.backupSession.Status.Snapshots {
		if snap.Phase == storageapi.SnapshotFailed {
			data = append(data, []string{Snapshot, fmt.Sprintf("%s failed", snap.Name)})
			failedSnapStatus = append(failedSnapStatus, snap)
		}
	}

	for _, rp := range opt.backupSession.Status.RetentionPolicies {
		if rp.Phase == coreapi.RetentionPolicyFailedToApply {
			data = append(data, []string{RetentionPolicy, rp.Error})
		}
	}

	_, err := fmt.Fprintf(os.Stdout, "Debugging BackupSession: %s/%s\n", opt.backupSession.Namespace, opt.backupSession.Name)
	if err != nil {
		return err
	}

	if err := createTable(data); err != nil {
		return err
	}

	for _, fs := range failedSnapStatus {
		if err := opt.showTableForFailedSnapshot(fs); err != nil {
			return err
		}
	}

	return nil
}

func (opt *backupDebugOptions) showTableForFailedSnapshot(snap coreapi.SnapshotStatus) error {
	snapshot := &storageapi.Snapshot{
		ObjectMeta: metav1.ObjectMeta{
			Name:      snap.Name,
			Namespace: srcNamespace,
		},
	}

	if err := klient.Get(context.Background(), client.ObjectKeyFromObject(snapshot), snapshot); err != nil {
		return err
	}

	var data [][]string

	for _, cond := range snapshot.Status.Conditions {
		if cond.Status == metav1.ConditionFalse {
			data = append(data, []string{Condition, cond.Message})
		}
	}

	componentFailed := false
	for name, comp := range snapshot.Status.Components {
		if comp.Phase == storageapi.ComponentPhaseFailed {
			componentFailed = true
			data = append(data, []string{Component, fmt.Sprintf("%s: %s", name, comp.Error)})
		}
	}

	_, err := fmt.Fprintf(os.Stdout, "Debugging Snapshot: %s/%s\n", snapshot.Namespace, snapshot.Name)
	if err != nil {
		return err
	}

	if err = createTable(data); err != nil {
		return err
	}

	if componentFailed {
		pods := core.PodList{}
		if err := klient.List(context.Background(), &pods, client.MatchingLabels(opt.getLabels())); err != nil {
			return err
		}

		for _, pod := range pods.Items {
			if err := showLogs(pod, "--all-containers"); err != nil {
				return err
			}
			_, err := fmt.Fprintf(os.Stdout, "\n\n")
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (opt *backupDebugOptions) getLabels() map[string]string {
	labels := opt.backupSession.OffshootLabels()
	labels[meta_util.ComponentLabelKey] = apis.KubeStashBackupComponent
	return labels
}
