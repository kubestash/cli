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
	"encoding/json"
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
	case v1beta1.ResourceKindBackupBlueprint:
		return convertBackupBlueprint(ri)
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
			Endpoint:   addConnectionScheme(repo.Spec.Backend.S3.Endpoint),
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

func addConnectionScheme(endpoint string) string {
	if strings.HasPrefix(endpoint, "http") {
		return endpoint
	}
	return "https://" + endpoint
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

	ns := oldBC.Spec.Repository.Namespace
	if ns == "" {
		ns = oldBC.Namespace
	}
	rp := createRetentionPolicy(oldBC.Spec.RetentionPolicy, ns)
	if err := writeToTargetDir(ri.Filename, true, rp); err != nil {
		return err
	}

	return nil
}

func createBackupConfiguration(oldBC *v1beta1.BackupConfiguration) *coreapi.BackupConfiguration {
	var ref v1beta1.TargetRef
	if oldBC.Spec.Target != nil {
		ref = v1beta1.TargetRef{
			APIVersion: oldBC.Spec.Target.Ref.APIVersion,
			Kind:       oldBC.Spec.Target.Ref.Kind,
			Name:       oldBC.Spec.Target.Ref.Name,
			Namespace:  oldBC.Spec.Target.Ref.Namespace,
		}
	}
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
			Target:   configureTarget(oldBC.Namespace, ref),
			Backends: []coreapi.BackendReference{configureBackend(oldBC)},
			Sessions: []coreapi.Session{configureSession(oldBC)},
		},
	}
}

func convertBackupBlueprint(ri parser.ResourceInfo) error {
	oldBB := &v1beta1.BackupBlueprint{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(ri.Object.Object, oldBB); err != nil {
		return err
	}

	newBC := createBackupBlueprint(oldBB)
	if err := writeToTargetDir(ri.Filename, false, newBC); err != nil {
		return err
	}

	if oldBB.Spec.Hooks != nil {
		if oldBB.Spec.Hooks.PreBackup != nil {
			ht := createHookTemplate(kmapi.ObjectReference{
				Name:      meta_util.ValidNameWithPrefixNSuffix(oldBB.Name, "prebackup", "hook"),
				Namespace: oldBB.Namespace,
			}, oldBB.Spec.Hooks.PreBackup)
			if err := writeToTargetDir(ri.Filename, true, ht); err != nil {
				return err
			}
		}

		if oldBB.Spec.Hooks.PostBackup != nil {
			ht := createHookTemplate(kmapi.ObjectReference{
				Name:      meta_util.ValidNameWithPrefixNSuffix(oldBB.Name, "postbackup", "hook"),
				Namespace: oldBB.Namespace,
			}, oldBB.Spec.Hooks.PostBackup.Handler)
			if err := writeToTargetDir(ri.Filename, true, ht); err != nil {
				return err
			}
		}
	}

	ns := oldBB.Spec.RepoNamespace
	if ns == "" {
		ns = oldBB.Namespace
	}
	rp := createRetentionPolicy(oldBB.Spec.RetentionPolicy, ns)
	if err := writeToTargetDir(ri.Filename, true, rp); err != nil {
		return err
	}

	return nil
}

func createBackupBlueprint(oldBB *v1beta1.BackupBlueprint) *coreapi.BackupBlueprint {
	return &coreapi.BackupBlueprint{
		TypeMeta: metav1.TypeMeta{
			Kind:       coreapi.ResourceKindBackupBlueprint,
			APIVersion: coreapi.GroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      oldBB.Name,
			Namespace: oldBB.Namespace,
		},
		Spec: coreapi.BackupBlueprintSpec{
			BackupConfigurationTemplate: &coreapi.BackupConfigurationTemplate{
				Namespace:      "",
				DeletionPolicy: "",
				Backends:       []coreapi.BackendReference{configureBackendFromBlueprint(oldBB)},
				Sessions:       []coreapi.Session{configureSessionFromBlueprint(oldBB)},
			},
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

func createRetentionPolicy(rp v1alpha1.RetentionPolicy, ns string) *storageapi.RetentionPolicy {
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
			Name:      rp.Name,
			Namespace: ns,
		},
		Spec: storageapi.RetentionPolicySpec{
			SuccessfulSnapshots: &storageapi.SuccessfulSnapshotsKeepPolicy{
				Last:    convertInt64ToInt32P(rp.KeepLast),
				Hourly:  convertInt64ToInt32P(rp.KeepHourly),
				Daily:   convertInt64ToInt32P(rp.KeepDaily),
				Weekly:  convertInt64ToInt32P(rp.KeepWeekly),
				Monthly: convertInt64ToInt32P(rp.KeepMonthly),
				Yearly:  convertInt64ToInt32P(rp.KeepYearly),
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

func configureTarget(namespace string, ref v1beta1.TargetRef) *kmapi.TypedObjectReference {
	if isTargetWorkload(ref) {
		if ref.Namespace != "" {
			namespace = ref.Namespace
		}
		return &kmapi.TypedObjectReference{
			APIGroup:  strings.Split(ref.APIVersion, "/")[0],
			Kind:      ref.Kind,
			Name:      ref.Name,
			Namespace: namespace,
		}
	}
	return &kmapi.TypedObjectReference{
		APIGroup:  setValidValue("APIGroup"),
		Kind:      setValidValue("Kind"),
		Name:      setValidValue("Name"),
		Namespace: setValidValue("Namespace"),
	}
}

func isTargetWorkload(ref v1beta1.TargetRef) bool {
	if ref.Kind == apis.KindStatefulSet ||
		ref.Kind == apis.KindDeployment ||
		ref.Kind == apis.KindDaemonSet {
		return true
	}
	return false
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

func configureBackendFromBlueprint(bb *v1beta1.BackupBlueprint) coreapi.BackendReference {
	ns := bb.Spec.RepoNamespace
	if ns == "" {
		ns = bb.Namespace
	}
	return coreapi.BackendReference{
		Name: "storage",
		StorageRef: &kmapi.ObjectReference{
			Name:      setValidValue("BackupStorage"),
			Namespace: setValidValue("Namespace"),
		},
		RetentionPolicy: &kmapi.ObjectReference{
			Name:      bb.Spec.RetentionPolicy.Name,
			Namespace: ns,
		},
	}
}

func configureSession(bc *v1beta1.BackupConfiguration) coreapi.Session {
	return coreapi.Session{
		SessionConfig: &coreapi.SessionConfig{
			Name:                "backup",
			SessionHistoryLimit: pointer.Int32(bc.Spec.BackupHistoryLimit),
			BackupTimeout:       bc.Spec.TimeOut,
			Hooks:               configureBackupHooks(bc.GetName(), bc.GetNamespace(), bc.Spec.Hooks),
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
		Addon: configureBackupAddonInfo(bc),
	}
}

func configureSessionFromBlueprint(bb *v1beta1.BackupBlueprint) coreapi.Session {
	return coreapi.Session{
		SessionConfig: &coreapi.SessionConfig{
			Name:                "backup",
			SessionHistoryLimit: pointer.Int32(bb.Spec.BackupHistoryLimit),
			BackupTimeout:       bb.Spec.TimeOut,
			Hooks:               configureBackupHooks(bb.GetName(), bb.GetNamespace(), bb.Spec.Hooks),
			Scheduler: &coreapi.SchedulerSpec{
				Schedule: bb.Spec.Schedule,
				JobTemplate: coreapi.JobTemplate{
					BackoffLimit: pointer.Int32P(1),
				},
			},
			RetryConfig: (*coreapi.RetryConfig)(bb.Spec.RetryConfig),
		},
		Repositories: []coreapi.RepositoryInfo{
			{
				Name:    fmt.Sprintf(`${repoName}`),
				Backend: "storage",
				Directory: filepath.Join(setValidValue("Directory"),
					fmt.Sprintf(`${namespace}/${targetName}`)),
				EncryptionSecret: &kmapi.ObjectReference{
					Name:      setValidValue("Name"),
					Namespace: setValidValue("Namespace"),
				},
			},
		},
		Addon: configureBackupAddonInfoFromBlueprint(bb),
	}
}

func configureBackupHooks(configName, configNs string, hooks *v1beta1.BackupHooks) *coreapi.BackupHooks {
	if hooks == nil {
		return nil
	}

	var preHook, postHook []coreapi.HookInfo
	if hooks.PreBackup != nil {
		preHook = append(preHook, coreapi.HookInfo{
			Name: "prebackup-hook",
			HookTemplate: &kmapi.ObjectReference{
				Name:      meta_util.ValidNameWithPrefixNSuffix(configName, "prebackup", "hook"),
				Namespace: configNs,
			},
		})
	}
	if hooks.PostBackup != nil {
		postHook = append(postHook, coreapi.HookInfo{
			Name: "postbackup-hook",
			HookTemplate: &kmapi.ObjectReference{
				Name:      meta_util.ValidNameWithPrefixNSuffix(configName, "postbackup", "hook"),
				Namespace: configName,
			},
			ExecutionPolicy: configureHookExecutionPolicy(hooks.PostBackup.ExecutionPolicy),
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

func configureBackupAddonInfo(bc *v1beta1.BackupConfiguration) *coreapi.AddonInfo {
	var podTemplateSpec *ofst.PodTemplateSpec
	if bc.Spec.RuntimeSettings.Pod != nil {
		podTemplateSpec = &ofst.PodTemplateSpec{
			Spec: configurePodRuntimeSettings(bc.Spec.RuntimeSettings.Pod),
		}
	}
	if bc.Spec.Target != nil && isTargetWorkload(bc.Spec.Target.Ref) {
		params := &runtime.RawExtension{}
		pathsMap := make(map[string]any)

		if len(bc.Spec.Target.Paths) > 0 {
			pathsMap["paths"] = strings.Join(bc.Spec.Target.Paths, ",")
		}
		if len(bc.Spec.Target.Exclude) > 0 {
			pathsMap["exclude"] = strings.Join(bc.Spec.Target.Exclude, ",")
		}
		if len(pathsMap) > 0 {
			data, _ := json.Marshal(pathsMap)
			params.Raw = data
		}

		return &coreapi.AddonInfo{
			Name: "workload-addon",
			Tasks: []coreapi.TaskReference{
				{
					Name:   "logical-backup",
					Params: params,
				},
			},
			ContainerRuntimeSettings: bc.Spec.RuntimeSettings.Container,
			JobTemplate:              podTemplateSpec,
		}
	}
	return &coreapi.AddonInfo{
		Name: setValidValue("Name"),
		Tasks: []coreapi.TaskReference{
			{
				Name: setValidValue("Name"),
			},
		},
		ContainerRuntimeSettings: bc.Spec.RuntimeSettings.Container,
		JobTemplate:              podTemplateSpec,
	}
}

func configureBackupAddonInfoFromBlueprint(bb *v1beta1.BackupBlueprint) *coreapi.AddonInfo {
	var podTemplateSpec *ofst.PodTemplateSpec
	if bb.Spec.RuntimeSettings.Pod != nil {
		podTemplateSpec = &ofst.PodTemplateSpec{
			Spec: configurePodRuntimeSettings(bb.Spec.RuntimeSettings.Pod),
		}
	}
	return &coreapi.AddonInfo{
		Name: setValidValue("Name"),
		Tasks: []coreapi.TaskReference{
			{
				Name: setValidValue("Name"),
			},
		},
		ContainerRuntimeSettings: bb.Spec.RuntimeSettings.Container,
		JobTemplate:              podTemplateSpec,
	}
}

func getRepoName(bb *v1beta1.BackupBlueprint) string {
	// TODO: bb.Spec.Repository.Name
	return bb.Name
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
		podSpec.ServiceAccountName = setValidValue("ServiceAccountName")
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
				Name:      meta_util.ValidNameWithPrefixNSuffix(oldRS.Name, "postrestore", "hook"),
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

	var ref v1beta1.TargetRef
	if oldRS.Spec.Target != nil {
		ref = oldRS.Spec.Target.Ref
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
			Target: configureTarget(oldRS.Namespace, ref),
			DataSource: &coreapi.RestoreDataSource{
				Namespace:  namespace,
				Repository: oldRS.Spec.Repository.Name,
				Snapshot:   setValidValue("Snapshot"),
				EncryptionSecret: &kmapi.ObjectReference{
					Name:      setValidValue("Name"),
					Namespace: setValidValue("Namespace"),
				},
			},
			Addon:          configureRestoreAddonInfo(oldRS),
			RestoreTimeout: oldRS.Spec.TimeOut,
			Hooks:          configureRestoreHooks(oldRS),
		},
	}
}

func configureRestoreAddonInfo(rs *v1beta1.RestoreSession) *coreapi.AddonInfo {
	var podTemplateSpec *ofst.PodTemplateSpec
	if rs.Spec.RuntimeSettings.Pod != nil {
		podTemplateSpec = &ofst.PodTemplateSpec{
			Spec: configurePodRuntimeSettings(rs.Spec.RuntimeSettings.Pod),
		}
	}
	if rs.Spec.Target != nil && isTargetWorkload(rs.Spec.Target.Ref) {
		// TODO: convert rules to params
		return &coreapi.AddonInfo{
			Name: "workload-addon",
			Tasks: []coreapi.TaskReference{
				{
					Name: "logical-backup-restore",
				},
			},
			ContainerRuntimeSettings: rs.Spec.RuntimeSettings.Container,
			JobTemplate:              podTemplateSpec,
		}
	}
	return &coreapi.AddonInfo{
		Name: setValidValue("Name"),
		Tasks: []coreapi.TaskReference{
			{
				Name: setValidValue("Name"),
			},
		},
		ContainerRuntimeSettings: rs.Spec.RuntimeSettings.Container,
		JobTemplate:              podTemplateSpec,
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
				Name:      meta_util.ValidNameWithPrefixNSuffix(rs.Name, "prerestore", "hook"),
				Namespace: rs.Namespace,
			},
		})
	}

	if rs.Spec.Hooks.PostRestore != nil {
		postHook = append(postHook, coreapi.HookInfo{
			Name: "postrestore-hook",
			HookTemplate: &kmapi.ObjectReference{
				Name:      meta_util.ValidNameWithPrefixNSuffix(rs.Name, "postrestore", "hook"),
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

func writeToTargetDir(srcPath string, addSeparator bool, obj any) error {
	targetPath := strings.ReplaceAll(srcPath, sourceDir, targetDir)
	if err := os.MkdirAll(filepath.Dir(targetPath), os.ModePerm); err != nil {
		return err
	}
	klog.Infof("Writing %s to %s", srcPath, targetPath)

	if addSeparator {
		if err := addSeparatorToTargetFile(targetPath); err != nil {
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
	defer closeFileWithLogError(file)
	if _, err := file.Write(marshalled); err != nil {
		return err
	}
	return nil
}

func addSeparatorToTargetFile(filePath string) error {
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, os.ModePerm)
	if err != nil {
		return err
	}
	defer closeFileWithLogError(file)
	separator := "\n---\n\n"
	if _, err := file.WriteString(separator); err != nil {
		return err
	}
	return nil
}

func closeFileWithLogError(file *os.File) {
	err := file.Close()
	if err != nil {
		klog.Errorf("Error closing file: %v", err)
	}
}
