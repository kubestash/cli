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
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"stash.appscode.dev/apimachinery/apis/stash/v1alpha1"
	"stash.appscode.dev/apimachinery/apis/stash/v1beta1"

	"github.com/spf13/cobra"
	"gomodules.xyz/flags"
	"gomodules.xyz/pointer"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/klog/v2"
	kmapi "kmodules.xyz/client-go/api/v1"
	core_util "kmodules.xyz/client-go/core/v1"
	meta_util "kmodules.xyz/client-go/meta"
	"kmodules.xyz/client-go/tools/parser"
	ofst "kmodules.xyz/offshoot-api/api/v1"
	prober "kmodules.xyz/prober/api/v1"
	"kubestash.dev/apimachinery/apis"
	coreapi "kubestash.dev/apimachinery/apis/core/v1alpha1"
	storageapi "kubestash.dev/apimachinery/apis/storage/v1alpha1"
	"sigs.k8s.io/yaml"
)

var sourceDir, targetDir string

func NewCmdConvert() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "convert",
		Short:             `Convert Stash resources yaml to Kubestash resources yaml`,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags.EnsureRequiredFlags(cmd, "source-dir", "target-dir")
			if err := parser.ProcessPath(sourceDir, convertResources); err != nil {
				return err
			}
			klog.Infof("Resources convertion completed successfully")
			return nil
		},
	}
	cmd.Flags().StringVar(&sourceDir, "source-dir", sourceDir, "Source directory.")
	cmd.Flags().StringVar(&targetDir, "target-dir", targetDir, "Target directory.")
	return cmd
}

func convertResources(ri parser.ResourceInfo) error {
	klog.Infof("Converting file: %s", ri.Filename)
	switch ri.Object.GetKind() {
	case v1alpha1.ResourceKindRepository:
		return convertRepository(ri)
	case v1beta1.ResourceKindBackupConfiguration:
		return convertBackupConfiguration(ri)
	case v1beta1.ResourceKindRestoreSession:
		return convertRestoreSession(ri)
	default:
		return nil
	}
}

func convertRepository(ri parser.ResourceInfo) error {
	repo := &v1alpha1.Repository{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(ri.Object.Object, repo); err != nil {
		return err
	}
	bs := createBackupStorage(repo)
	return writeToTargetDir(ri.Filename, false, bs)
}

func createBackupStorage(repo *v1alpha1.Repository) *storageapi.BackupStorage {
	bs := &storageapi.BackupStorage{
		TypeMeta: metav1.TypeMeta{
			Kind:       storageapi.ResourceKindBackupStorage,
			APIVersion: storageapi.GroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      repo.Name,
			Namespace: repo.Namespace,
		},
	}

	if repo.Spec.UsagePolicy != nil {
		bs.Spec.UsagePolicy = configureUsagePolicy(repo.Spec.UsagePolicy)
	}
	if repo.Spec.WipeOut {
		bs.Spec.DeletionPolicy = storageapi.DeletionPolicyWipeOut
	}

	configureStorageBackend(repo, bs)
	return bs
}

func configureStorageBackend(repo *v1alpha1.Repository, bs *storageapi.BackupStorage) {
	switch {
	case repo.Spec.Backend.S3 != nil:
		bs.Spec.Storage.Provider = storageapi.ProviderS3
		bs.Spec.Storage.S3 = &storageapi.S3Spec{
			Endpoint:   repo.Spec.Backend.S3.Endpoint,
			Bucket:     repo.Spec.Backend.S3.Bucket,
			Prefix:     repo.Spec.Backend.S3.Prefix,
			Region:     repo.Spec.Backend.S3.Region,
			SecretName: repo.Spec.Backend.StorageSecretName,
		}
	case repo.Spec.Backend.GCS != nil:
		bs.Spec.Storage.Provider = storageapi.ProviderGCS
		bs.Spec.Storage.GCS = &storageapi.GCSSpec{
			Bucket:         repo.Spec.Backend.GCS.Bucket,
			Prefix:         repo.Spec.Backend.GCS.Prefix,
			MaxConnections: repo.Spec.Backend.GCS.MaxConnections,
			SecretName:     repo.Spec.Backend.StorageSecretName,
		}
	case repo.Spec.Backend.Azure != nil:
		bs.Spec.Storage.Provider = storageapi.ProviderAzure
		bs.Spec.Storage.Azure = &storageapi.AzureSpec{
			Container:      repo.Spec.Backend.Azure.Container,
			Prefix:         repo.Spec.Backend.Azure.Prefix,
			MaxConnections: repo.Spec.Backend.Azure.MaxConnections,
			StorageAccount: setValidValue("StorageAccount"),
		}
	case repo.Spec.Backend.Local != nil:
		bs.Spec.Storage.Provider = storageapi.ProviderLocal
		bs.Spec.Storage.Local = &storageapi.LocalSpec{
			// TODO: Configure VolumeSource
			MountPath: repo.Spec.Backend.Local.MountPath,
			SubPath:   repo.Spec.Backend.Local.SubPath,
		}
	}
}

func convertBackupConfiguration(ri parser.ResourceInfo) error {
	oldBC := &v1beta1.BackupConfiguration{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(ri.Object.Object, oldBC); err != nil {
		return err
	}

	newBC := createBackupConfiguration(oldBC)
	if err := writeToTargetDir(ri.Filename, false, newBC); err != nil {
		return err
	}

	if oldBC.Spec.Hooks != nil {
		if oldBC.Spec.Hooks.PreBackup != nil {
			ht := createHookTemplate(kmapi.ObjectReference{
				Name:      meta_util.ValidNameWithPrefixNSuffix(oldBC.Name, "prebackup", "hook"),
				Namespace: oldBC.Namespace,
			}, oldBC.Spec.Hooks.PreBackup)
			if err := writeToTargetDir(ri.Filename, true, ht); err != nil {
				return err
			}
		}

		if oldBC.Spec.Hooks.PostBackup != nil {
			ht := createHookTemplate(kmapi.ObjectReference{
				Name:      meta_util.ValidNameWithPrefixNSuffix(oldBC.Name, "postbackup", "hook"),
				Namespace: oldBC.Namespace,
			}, oldBC.Spec.Hooks.PostBackup.Handler)
			if err := writeToTargetDir(ri.Filename, true, ht); err != nil {
				return err
			}
		}
	}

	rp := createRetentionPolicy(oldBC)
	if err := writeToTargetDir(ri.Filename, true, rp); err != nil {
		return err
	}

	return nil
}

func createBackupConfiguration(oldBC *v1beta1.BackupConfiguration) *coreapi.BackupConfiguration {
	return &coreapi.BackupConfiguration{
		TypeMeta: metav1.TypeMeta{
			Kind:       coreapi.ResourceKindBackupConfiguration,
			APIVersion: coreapi.GroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      oldBC.Name,
			Namespace: oldBC.Namespace,
		},
		Spec: coreapi.BackupConfigurationSpec{
			Paused:   oldBC.Spec.Paused,
			Target:   configureTarget(),
			Backends: []coreapi.BackendReference{configureBackend(oldBC)},
			Sessions: []coreapi.Session{configureSession(oldBC)},
		},
	}
}

func createHookTemplate(objRef kmapi.ObjectReference, handler *prober.Handler) *coreapi.HookTemplate {
	if handler == nil {
		return nil
	}

	executor := &coreapi.HookExecutor{}
	switch {
	case handler.HTTPPost != nil || handler.HTTPGet != nil:
		executor.Type = coreapi.HookExecutorOperator
	case handler.Exec != nil:
		executor.Type = coreapi.HookExecutorPod
		executor.Pod = &coreapi.PodHookExecutorSpec{
			Selector: setValidValue("Selector"),
		}
	}
	return &coreapi.HookTemplate{
		TypeMeta: metav1.TypeMeta{
			Kind:       coreapi.ResourceKindHookTemplate,
			APIVersion: coreapi.GroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      objRef.Name,
			Namespace: objRef.Namespace,
		},
		Spec: coreapi.HookTemplateSpec{
			Action:   handler,
			Executor: executor,
		},
	}
}

func createRetentionPolicy(bc *v1beta1.BackupConfiguration) *storageapi.RetentionPolicy {
	namespace := bc.Namespace
	if bc.Spec.Repository.Namespace != "" {
		namespace = bc.Spec.Repository.Namespace
	}

	convertInt64ToInt32P := func(i int64) *int32 {
		if i <= 0 {
			return nil
		}
		return pointer.Int32P(int32(i))
	}

	return &storageapi.RetentionPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       storageapi.ResourceKindRetentionPolicy,
			APIVersion: storageapi.GroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      bc.Spec.RetentionPolicy.Name,
			Namespace: namespace,
		},
		Spec: storageapi.RetentionPolicySpec{
			SuccessfulSnapshots: &storageapi.SuccessfulSnapshotsKeepPolicy{
				Last:    convertInt64ToInt32P(bc.Spec.RetentionPolicy.KeepLast),
				Hourly:  convertInt64ToInt32P(bc.Spec.RetentionPolicy.KeepHourly),
				Daily:   convertInt64ToInt32P(bc.Spec.RetentionPolicy.KeepDaily),
				Weekly:  convertInt64ToInt32P(bc.Spec.RetentionPolicy.KeepWeekly),
				Monthly: convertInt64ToInt32P(bc.Spec.RetentionPolicy.KeepMonthly),
				Yearly:  convertInt64ToInt32P(bc.Spec.RetentionPolicy.KeepYearly),
			},
		},
	}
}

func configureUsagePolicy(policy *v1alpha1.UsagePolicy) *apis.UsagePolicy {
	if policy.AllowedNamespaces.From == nil {
		return nil
	}

	switch *policy.AllowedNamespaces.From {
	case v1alpha1.NamespacesFromAll:
		fromAll := apis.NamespacesFromAll
		return &apis.UsagePolicy{AllowedNamespaces: apis.AllowedNamespaces{From: &fromAll}}
	case v1alpha1.NamespacesFromSame:
		fromSame := apis.NamespacesFromSame
		return &apis.UsagePolicy{AllowedNamespaces: apis.AllowedNamespaces{From: &fromSame}}
	case v1alpha1.NamespacesFromSelector:
		fromSelector := apis.NamespacesFromSelector
		return &apis.UsagePolicy{AllowedNamespaces: apis.AllowedNamespaces{
			From:     &fromSelector,
			Selector: policy.AllowedNamespaces.Selector,
		}}
	default:
		return nil
	}
}

func configureTarget() *kmapi.TypedObjectReference {
	return &kmapi.TypedObjectReference{
		APIGroup:  setValidValue("APIGroup"),
		Kind:      setValidValue("Kind"),
		Name:      setValidValue("Name"),
		Namespace: setValidValue("Namespace"),
	}
}

func configureBackend(bc *v1beta1.BackupConfiguration) coreapi.BackendReference {
	namespace := bc.Namespace
	if bc.Spec.Repository.Namespace != "" {
		namespace = bc.Spec.Repository.Namespace
	}
	return coreapi.BackendReference{
		Name: "storage",
		StorageRef: &kmapi.ObjectReference{
			Name:      bc.Spec.Repository.Name,
			Namespace: namespace,
		},
		RetentionPolicy: &kmapi.ObjectReference{
			Name:      bc.Spec.RetentionPolicy.Name,
			Namespace: namespace,
		},
	}
}

func configureSession(bc *v1beta1.BackupConfiguration) coreapi.Session {
	return coreapi.Session{
		SessionConfig: &coreapi.SessionConfig{
			Name:                "backup",
			SessionHistoryLimit: pointer.Int32(bc.Spec.BackupHistoryLimit),
			BackupTimeout:       bc.Spec.TimeOut,
			Hooks:               configureBackupHooks(bc),
			Scheduler: &coreapi.SchedulerSpec{
				Schedule: bc.Spec.Schedule,
				JobTemplate: coreapi.JobTemplate{
					BackoffLimit: pointer.Int32P(1),
				},
			},
			RetryConfig: (*coreapi.RetryConfig)(bc.Spec.RetryConfig),
		},
		Repositories: []coreapi.RepositoryInfo{
			{
				Name:      bc.Spec.Repository.Name,
				Backend:   "storage",
				Directory: setValidValue("Directory"),
				EncryptionSecret: &kmapi.ObjectReference{
					Name:      setValidValue("Name"),
					Namespace: setValidValue("Namespace"),
				},
			},
		},
		Addon: &coreapi.AddonInfo{
			Name: setValidValue("Name"),
			Tasks: []coreapi.TaskReference{
				{
					Name: setValidValue("Name"),
				},
			},
			ContainerRuntimeSettings: bc.Spec.RuntimeSettings.Container,
			JobTemplate: &ofst.PodTemplateSpec{
				Spec: configurePodRuntimeSettings(bc.Spec.RuntimeSettings.Pod),
			},
		},
	}
}

func configureBackupHooks(bc *v1beta1.BackupConfiguration) *coreapi.BackupHooks {
	if bc.Spec.Hooks == nil {
		return nil
	}

	var preHook, postHook []coreapi.HookInfo
	if bc.Spec.Hooks.PreBackup != nil {
		preHook = append(preHook, coreapi.HookInfo{
			Name: "prebackup-hook",
			HookTemplate: &kmapi.ObjectReference{
				Name:      fmt.Sprintf("%s-prebackup-hook", bc.Name),
				Namespace: bc.Namespace,
			},
		})
	}
	if bc.Spec.Hooks.PostBackup != nil {
		postHook = append(postHook, coreapi.HookInfo{
			Name: "postbackup-hook",
			HookTemplate: &kmapi.ObjectReference{
				Name:      fmt.Sprintf("%s-postbackup-hook", bc.Name),
				Namespace: bc.Namespace,
			},
			ExecutionPolicy: configureHookExecutionPolicy(bc.Spec.Hooks.PostBackup.ExecutionPolicy),
		})
	}
	return &coreapi.BackupHooks{
		PreBackup:  preHook,
		PostBackup: postHook,
	}
}

func configureHookExecutionPolicy(policy v1beta1.HookExecutionPolicy) coreapi.HookExecutionPolicy {
	switch policy {
	case v1beta1.ExecuteAlways:
		return coreapi.ExecuteAlways
	case v1beta1.ExecuteOnSuccess:
		return coreapi.ExecuteOnSuccess
	case v1beta1.ExecuteOnFailure:
		return coreapi.ExecuteOnFailure
	default:
		return ""
	}
}

func configurePodRuntimeSettings(settings *ofst.PodRuntimeSettings) ofst.PodSpec {
	if settings == nil {
		return ofst.PodSpec{}
	}

	var podSpec ofst.PodSpec

	if len(settings.NodeSelector) > 0 {
		podSpec.NodeSelector = settings.NodeSelector
	}
	if settings.ServiceAccountName != "" {
		podSpec.ServiceAccountName = settings.ServiceAccountName
	}
	if settings.SecurityContext != nil {
		podSpec.SecurityContext = settings.SecurityContext
	}
	if len(settings.ImagePullSecrets) > 0 {
		podSpec.ImagePullSecrets = core_util.MergeLocalObjectReferences(podSpec.ImagePullSecrets, settings.ImagePullSecrets)
	}
	if settings.Affinity != nil {
		podSpec.Affinity = settings.Affinity
	}
	if settings.SchedulerName != "" {
		podSpec.SchedulerName = settings.SchedulerName
	}
	if len(settings.Tolerations) > 0 {
		podSpec.Tolerations = settings.Tolerations
	}
	if settings.PriorityClassName != "" {
		podSpec.PriorityClassName = settings.PriorityClassName
	}
	if settings.Priority != nil {
		podSpec.Priority = settings.Priority
	}
	if settings.RuntimeClassName != nil {
		podSpec.RuntimeClassName = settings.RuntimeClassName
	}
	if settings.EnableServiceLinks != nil {
		podSpec.EnableServiceLinks = settings.EnableServiceLinks
	}
	if settings.TopologySpreadConstraints != nil {
		podSpec.TopologySpreadConstraints = settings.TopologySpreadConstraints
	}
	return podSpec
}

func convertRestoreSession(ri parser.ResourceInfo) error {
	oldRS := &v1beta1.RestoreSession{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(ri.Object.Object, oldRS); err != nil {
		return err
	}

	newRS := createRestoreSession(oldRS)
	if err := writeToTargetDir(ri.Filename, false, newRS); err != nil {
		return err
	}

	if oldRS.Spec.Hooks != nil {
		if oldRS.Spec.Hooks.PreRestore != nil {
			ht := createHookTemplate(kmapi.ObjectReference{
				Name:      meta_util.ValidNameWithPrefixNSuffix(oldRS.Name, "prerestore", "hook"),
				Namespace: oldRS.Namespace,
			}, oldRS.Spec.Hooks.PreRestore)
			if err := writeToTargetDir(ri.Filename, true, ht); err != nil {
				return err
			}
		}

		if oldRS.Spec.Hooks.PostRestore != nil {
			ht := createHookTemplate(kmapi.ObjectReference{
				Name:      meta_util.ValidNameWithPrefixNSuffix(oldRS.Name, "prerestore", "hook"),
				Namespace: oldRS.Namespace,
			}, oldRS.Spec.Hooks.PostRestore.Handler)
			if err := writeToTargetDir(ri.Filename, true, ht); err != nil {
				return err
			}
		}
	}
	return nil
}

func createRestoreSession(oldRS *v1beta1.RestoreSession) *coreapi.RestoreSession {
	namespace := oldRS.Namespace
	if oldRS.Spec.Repository.Namespace != "" {
		namespace = oldRS.Spec.Repository.Namespace
	}

	return &coreapi.RestoreSession{
		TypeMeta: metav1.TypeMeta{
			Kind:       coreapi.ResourceKindRestoreSession,
			APIVersion: coreapi.GroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      oldRS.Name,
			Namespace: oldRS.Namespace,
		},
		Spec: coreapi.RestoreSessionSpec{
			Target: configureTarget(),
			DataSource: &coreapi.RestoreDataSource{
				Namespace:  namespace,
				Repository: oldRS.Spec.Repository.Name,
				Snapshot:   setValidValue("Snapshot"),
				EncryptionSecret: &kmapi.ObjectReference{
					Name:      setValidValue("Name"),
					Namespace: setValidValue("Namespace"),
				},
			},
			Addon: &coreapi.AddonInfo{
				Name: setValidValue("Name"),
				Tasks: []coreapi.TaskReference{
					{
						Name: setValidValue("Name"),
					},
				},
				ContainerRuntimeSettings: oldRS.Spec.RuntimeSettings.Container,
				JobTemplate: &ofst.PodTemplateSpec{
					Spec: configurePodRuntimeSettings(oldRS.Spec.RuntimeSettings.Pod),
				},
			},
			RestoreTimeout: oldRS.Spec.TimeOut,
			Hooks:          configureRestoreHooks(oldRS),
		},
	}
}

func configureRestoreHooks(rs *v1beta1.RestoreSession) *coreapi.RestoreHooks {
	if rs.Spec.Hooks == nil {
		return nil
	}

	var preHook, postHook []coreapi.HookInfo
	if rs.Spec.Hooks.PreRestore != nil {
		preHook = append(preHook, coreapi.HookInfo{
			Name: "prerestore-hook",
			HookTemplate: &kmapi.ObjectReference{
				Name:      fmt.Sprintf("%s-prerestore-hook", rs.Name),
				Namespace: rs.Namespace,
			},
		})
	}

	if rs.Spec.Hooks.PostRestore != nil {
		postHook = append(postHook, coreapi.HookInfo{
			Name: "postrestore-hook",
			HookTemplate: &kmapi.ObjectReference{
				Name:      fmt.Sprintf("%s-postrestore-hook", rs.Name),
				Namespace: rs.Namespace,
			},
			ExecutionPolicy: configureHookExecutionPolicy(rs.Spec.Hooks.PostRestore.ExecutionPolicy),
		})
	}
	return &coreapi.RestoreHooks{
		PreRestore:  preHook,
		PostRestore: postHook,
	}
}

func setValidValue(fieldName string) string {
	return fmt.Sprintf("### Set Valid %s ###", fieldName)
}

func writeToTargetDir(srcPath string, separator bool, obj interface{}) error {
	targetPath := strings.Replace(srcPath, sourceDir, targetDir, -1)
	if err := os.MkdirAll(filepath.Dir(targetPath), os.ModePerm); err != nil {
		return err
	}
	klog.Infof("Writing %s to %s", srcPath, targetPath)

	if separator {
		if err := addSeparator(targetPath); err != nil {
			return err
		}
	}

	marshalled, err := yaml.Marshal(obj)
	if err != nil {
		return err
	}

	file, err := os.OpenFile(targetPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, os.ModePerm)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(marshalled); err != nil {
		return err
	}
	return nil
}

func addSeparator(path string) error {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, os.ModePerm)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.WriteString("\n---\n\n"); err != nil {
		return err
	}
	return nil
}
