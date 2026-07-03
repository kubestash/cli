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

package convert

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"

	"stash.appscode.dev/apimachinery/apis/stash/v1alpha1"
	"stash.appscode.dev/apimachinery/apis/stash/v1beta1"

	"gomodules.xyz/pointer"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/klog/v2"
	kmapi "kmodules.xyz/client-go/api/v1"
	core_util "kmodules.xyz/client-go/core/v1"
	meta_util "kmodules.xyz/client-go/meta"
	"kmodules.xyz/client-go/tools/parser"
	appcatalogapi "kmodules.xyz/custom-resources/apis/appcatalog/v1alpha1"
	ofst "kmodules.xyz/offshoot-api/api/v1"
	prober "kmodules.xyz/prober/api/v1"
	catalog "kubedb.dev/apimachinery/apis/catalog"
	"kubestash.dev/apimachinery/apis"
	coreapi "kubestash.dev/apimachinery/apis/core/v1alpha1"
	storageapi "kubestash.dev/apimachinery/apis/storage/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// resticPasswordKey is the data key holding the encryption password in a Stash
// storage Secret; the converted KubeStash encryption Secret carries only this key.
const resticPasswordKey = "RESTIC_PASSWORD"

// resolvedTarget holds values looked up from the cluster for an AppBinding target.
type resolvedTarget struct {
	target    *kmapi.TypedObjectReference // from AppBinding.spec.appRef
	addonName string                      // from <Kind>Version.spec.archiver.addon.name
}

// resolveAppBindingTarget resolves a Stash AppBinding target into the real KubeDB
// target and its KubeStash addon by querying the cluster.
//
// It returns (nil, nil) when the cluster is unreachable so callers fall back to the
// existing placeholder behaviour. It returns an error only when the cluster is
// reachable but the referenced AppBinding/version genuinely does not exist.
func resolveAppBindingTarget(ref v1beta1.TargetRef, defaultNS string) (*resolvedTarget, error) {
	ns := ref.Namespace
	if ns == "" {
		ns = defaultNS
	}

	ab := &appcatalogapi.AppBinding{}
	key := client.ObjectKey{Name: ref.Name, Namespace: ns}
	if err := klient.Get(context.Background(), key, ab); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, err
		}
		klog.Warningf("Cluster unreachable while resolving AppBinding %s/%s, keeping placeholders. Reason: %v", ns, ref.Name, err)
		return nil, nil
	}

	if ab.Spec.AppRef == nil {
		klog.Warningf("AppBinding %s/%s has no spec.appRef, keeping placeholders.", ns, ref.Name)
		return nil, nil
	}

	target := &kmapi.TypedObjectReference{
		APIGroup:  ab.Spec.AppRef.APIGroup,
		Kind:      ab.Spec.AppRef.Kind,
		Name:      ab.Spec.AppRef.Name,
		Namespace: ab.Spec.AppRef.Namespace,
	}
	if target.Namespace == "" {
		target.Namespace = ab.Namespace
	}

	addonName, err := resolveAddonName(ab)
	if err != nil {
		return nil, err
	}

	return &resolvedTarget{target: target, addonName: addonName}, nil
}

// resolveAddonName derives the KubeStash addon name for an AppBinding. It prefers the
// authoritative spec.archiver.addon.name on the KubeDB catalog version object, falling
// back to the "<kind>-addon" convention.
func resolveAddonName(ab *appcatalogapi.AppBinding) (string, error) {
	fallback := strings.ToLower(ab.Spec.AppRef.Kind) + "-addon"

	if ab.Spec.Version == "" {
		return fallback, nil
	}

	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   catalog.GroupName,
		Version: "v1alpha1",
		Kind:    ab.Spec.AppRef.Kind + "Version",
	})
	key := client.ObjectKey{Name: ab.Spec.Version}
	if err := klient.Get(context.Background(), key, u); err != nil {
		if apierrors.IsNotFound(err) {
			return "", err
		}
		klog.Warningf("Cluster unreachable while resolving %sVersion %q, using %q. Reason: %v", ab.Spec.AppRef.Kind, ab.Spec.Version, fallback, err)
		return fallback, nil
	}

	name, found, err := unstructured.NestedString(u.Object, "spec", "archiver", "addon", "name")
	if err != nil || !found || name == "" {
		return fallback, nil
	}
	return name, nil
}

func convertRepository(ri parser.ResourceInfo) error {
	repo := &v1alpha1.Repository{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(ri.Object.Object, repo); err != nil {
		return err
	}
	bs := createBackupStorage(repo)
	if err := writeToTargetDir(ri.Filename, bs); err != nil {
		return err
	}

	if secret := buildEncryptionSecret(repo); secret != nil {
		return writeToTargetDir(ri.Filename, secret)
	}
	return nil
}

// buildEncryptionSecret returns an encryption Secret carrying only the RESTIC_PASSWORD
// copied from the Repository's storage Secret. It returns nil when the user supplies
// their own encryption Secret via flags, or when the RESTIC_PASSWORD cannot be read
// from the cluster (unreachable / missing / key absent) so callers keep placeholders.
func buildEncryptionSecret(repo *v1alpha1.Repository) *core.Secret {
	if encryptionSecretName != "" || encryptionSecretNamespace != "" {
		return nil
	}
	password, ok := resticPasswordFromStorageSecret(repo.Spec.Backend.StorageSecretName, repo.Namespace)
	if !ok {
		return nil
	}
	return &core.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: core.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      encryptionSecretNameFor(repo.Name),
			Namespace: repo.Namespace,
		},
		Type: core.SecretTypeOpaque,
		Data: map[string][]byte{
			resticPasswordKey: password,
		},
	}
}

// encryptionSecretNameFor is the name of the encryption Secret generated for a Repository.
func encryptionSecretNameFor(repoName string) string {
	return repoName + "-encryption-secret"
}

// resticPasswordFromStorageSecret reads RESTIC_PASSWORD from a Stash storage Secret.
// It soft-fails (returns ok=false, logs) when the cluster is unreachable, the Secret
// is missing, or the key is absent, matching resolveAppBindingTarget's placeholder style.
func resticPasswordFromStorageSecret(secretName, namespace string) ([]byte, bool) {
	if secretName == "" {
		return nil, false
	}
	secret := &core.Secret{}
	key := client.ObjectKey{Name: secretName, Namespace: namespace}
	if err := klient.Get(context.Background(), key, secret); err != nil {
		if apierrors.IsNotFound(err) {
			klog.Warningf("Storage Secret %s/%s not found; keeping encryption Secret placeholders.", namespace, secretName)
		} else {
			klog.Warningf("Cluster unreachable while reading Storage Secret %s/%s; keeping encryption Secret placeholders. Reason: %v", namespace, secretName, err)
		}
		return nil, false
	}
	password, ok := secret.Data[resticPasswordKey]
	if !ok || len(password) == 0 {
		klog.Warningf("Storage Secret %s/%s has no %s; keeping encryption Secret placeholders.", namespace, secretName, resticPasswordKey)
		return nil, false
	}
	return password, true
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

	var rt *resolvedTarget
	if oldBC.Spec.Target != nil && oldBC.Spec.Target.Ref.Kind == appcatalogapi.ResourceKindApp {
		var err error
		rt, err = resolveAppBindingTarget(oldBC.Spec.Target.Ref, oldBC.Namespace)
		if err != nil {
			return err
		}
	}

	repoNS := oldBC.Spec.Repository.Namespace
	if repoNS == "" {
		repoNS = oldBC.Namespace
	}
	encRef, encResolved := encryptionSecretRef(oldBC.Spec.Repository.Name, repoNS)

	newBC := createBackupConfiguration(oldBC, rt, encRef)
	if err := writeToTargetDirWithComments(ri.Filename, newBC, repositoryComments(rt, encResolved)); err != nil {
		return err
	}

	if oldBC.Spec.Hooks != nil {
		if oldBC.Spec.Hooks.PreBackup != nil {
			ht := createHookTemplate(kmapi.ObjectReference{
				Name:      meta_util.ValidNameWithPrefixNSuffix(oldBC.Name, "prebackup", "hook"),
				Namespace: oldBC.Namespace,
			}, oldBC.Spec.Hooks.PreBackup)
			if err := writeToTargetDir(ri.Filename, ht); err != nil {
				return err
			}
		}

		if oldBC.Spec.Hooks.PostBackup != nil {
			ht := createHookTemplate(kmapi.ObjectReference{
				Name:      meta_util.ValidNameWithPrefixNSuffix(oldBC.Name, "postbackup", "hook"),
				Namespace: oldBC.Namespace,
			}, oldBC.Spec.Hooks.PostBackup.Handler)
			if err := writeToTargetDir(ri.Filename, ht); err != nil {
				return err
			}
		}
	}

	rp := createRetentionPolicy(oldBC.Spec.RetentionPolicy, repoNS)
	if err := writeToTargetDir(ri.Filename, rp); err != nil {
		return err
	}

	return nil
}

func createBackupConfiguration(oldBC *v1beta1.BackupConfiguration, rt *resolvedTarget, encRef *kmapi.ObjectReference) *coreapi.BackupConfiguration {
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
			Target:   configureTarget(oldBC.Namespace, ref, rt),
			Backends: []coreapi.BackendReference{configureBackend(oldBC)},
			Sessions: []coreapi.Session{configureSession(oldBC, rt, encRef)},
		},
	}
}

func convertBackupBlueprint(ri parser.ResourceInfo) error {
	oldBB := &v1beta1.BackupBlueprint{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(ri.Object.Object, oldBB); err != nil {
		return err
	}

	newBC := createBackupBlueprint(oldBB)
	if err := writeToTargetDir(ri.Filename, newBC); err != nil {
		return err
	}

	if oldBB.Spec.Hooks != nil {
		if oldBB.Spec.Hooks.PreBackup != nil {
			ht := createHookTemplate(kmapi.ObjectReference{
				Name:      meta_util.ValidNameWithPrefixNSuffix(oldBB.Name, "prebackup", "hook"),
				Namespace: oldBB.Namespace,
			}, oldBB.Spec.Hooks.PreBackup)
			if err := writeToTargetDir(ri.Filename, ht); err != nil {
				return err
			}
		}

		if oldBB.Spec.Hooks.PostBackup != nil {
			ht := createHookTemplate(kmapi.ObjectReference{
				Name:      meta_util.ValidNameWithPrefixNSuffix(oldBB.Name, "postbackup", "hook"),
				Namespace: oldBB.Namespace,
			}, oldBB.Spec.Hooks.PostBackup.Handler)
			if err := writeToTargetDir(ri.Filename, ht); err != nil {
				return err
			}
		}
	}

	ns := oldBB.Spec.RepoNamespace
	if ns == "" {
		ns = oldBB.Namespace
	}
	rp := createRetentionPolicy(oldBB.Spec.RetentionPolicy, ns)
	if err := writeToTargetDir(ri.Filename, rp); err != nil {
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

func configureTarget(namespace string, ref v1beta1.TargetRef, rt *resolvedTarget) *kmapi.TypedObjectReference {
	if rt != nil {
		return rt.target
	}
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

func configureSession(bc *v1beta1.BackupConfiguration, rt *resolvedTarget, encRef *kmapi.ObjectReference) coreapi.Session {
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
				Name:             bc.Spec.Repository.Name,
				Backend:          "storage",
				Directory:        repositoryDirectory(rt),
				EncryptionSecret: encRef,
			},
		},
		Addon: configureBackupAddonInfo(bc, rt),
	}
}

// encryptionSecretRef returns the encryption Secret reference for a session together
// with whether it fully resolved (no placeholder). The CLI flags win when set; when
// both are empty it references the Secret generated from the Repository's storage
// Secret (see buildEncryptionSecret), otherwise it falls back to placeholders.
func encryptionSecretRef(repoName, repoNamespace string) (*kmapi.ObjectReference, bool) {
	if encryptionSecretName != "" || encryptionSecretNamespace != "" {
		name := encryptionSecretName
		if name == "" {
			name = setValidValue("Name")
		}
		namespace := encryptionSecretNamespace
		if namespace == "" {
			namespace = setValidValue("Namespace")
		}
		resolved := encryptionSecretName != "" && encryptionSecretNamespace != ""
		return &kmapi.ObjectReference{Name: name, Namespace: namespace}, resolved
	}

	if generatedEncryptionSecretExists(repoName, repoNamespace) {
		return &kmapi.ObjectReference{
			Name:      encryptionSecretNameFor(repoName),
			Namespace: repoNamespace,
		}, true
	}
	return &kmapi.ObjectReference{
		Name:      setValidValue("Name"),
		Namespace: setValidValue("Namespace"),
	}, false
}

// generatedEncryptionSecretExists reports whether convertRepository would have
// generated an encryption Secret for the given Stash Repository, i.e. its storage
// Secret carries a RESTIC_PASSWORD. The Repository is looked up from the cluster so
// the session reference stays consistent with generation regardless of the order in
// which resources are processed.
func generatedEncryptionSecretExists(repoName, repoNamespace string) bool {
	repo := &v1alpha1.Repository{}
	key := client.ObjectKey{Name: repoName, Namespace: repoNamespace}
	if err := klient.Get(context.Background(), key, repo); err != nil {
		if !apierrors.IsNotFound(err) {
			klog.Warningf("Cluster unreachable while reading Repository %s/%s; keeping encryption Secret placeholders. Reason: %v", repoNamespace, repoName, err)
		}
		return false
	}
	_, ok := resticPasswordFromStorageSecret(repo.Spec.Backend.StorageSecretName, repo.Namespace)
	return ok
}

// repositoryDirectory derives the repository directory from the resolved target,
// falling back to a placeholder when the target could not be resolved.
func repositoryDirectory(rt *resolvedTarget) string {
	if rt != nil {
		return filepath.Join(rt.target.Namespace, rt.target.Name)
	}
	return setValidValue("Directory")
}

// repositoryComments builds the review line-comments to attach to the generated YAML.
func repositoryComments(rt *resolvedTarget, encResolved bool) map[string]string {
	comments := map[string]string{}
	if rt != nil {
		comments["directory"] = "review: <namespace>/<name> of the target database"
	}
	if !encResolved {
		comments["encryptionSecret"] = "review: set via --encryption-secret-name / --encryption-secret-namespace"
	}
	return comments
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
				Name:      `${repoName}`,
				Backend:   "storage",
				Directory: filepath.Join(setValidValue("Directory"), `${namespace}/${targetName}`),
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

func configureBackupAddonInfo(bc *v1beta1.BackupConfiguration, rt *resolvedTarget) *coreapi.AddonInfo {
	var podTemplateSpec *ofst.PodTemplateSpec
	if bc.Spec.RuntimeSettings.Pod != nil {
		podTemplateSpec = &ofst.PodTemplateSpec{
			Spec: configurePodRuntimeSettings(bc.Spec.RuntimeSettings.Pod),
		}
	}
	if rt != nil {
		return &coreapi.AddonInfo{
			Name: rt.addonName,
			Tasks: []coreapi.TaskReference{
				{
					Name: apis.LogicalBackup,
				},
			},
			ContainerRuntimeSettings: bc.Spec.RuntimeSettings.Container,
			JobTemplate:              podTemplateSpec,
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

	var rt *resolvedTarget
	if oldRS.Spec.Target != nil && oldRS.Spec.Target.Ref.Kind == appcatalogapi.ResourceKindApp {
		var err error
		rt, err = resolveAppBindingTarget(oldRS.Spec.Target.Ref, oldRS.Namespace)
		if err != nil {
			return err
		}
	}

	repoNS := oldRS.Spec.Repository.Namespace
	if repoNS == "" {
		repoNS = oldRS.Namespace
	}
	encRef, encResolved := encryptionSecretRef(oldRS.Spec.Repository.Name, repoNS)

	newRS := createRestoreSession(oldRS, rt, encRef)
	if err := writeToTargetDirWithComments(ri.Filename, newRS, restoreSessionComments(encResolved)); err != nil {
		return err
	}

	if oldRS.Spec.Hooks != nil {
		if oldRS.Spec.Hooks.PreRestore != nil {
			ht := createHookTemplate(kmapi.ObjectReference{
				Name:      meta_util.ValidNameWithPrefixNSuffix(oldRS.Name, "prerestore", "hook"),
				Namespace: oldRS.Namespace,
			}, oldRS.Spec.Hooks.PreRestore)
			if err := writeToTargetDir(ri.Filename, ht); err != nil {
				return err
			}
		}

		if oldRS.Spec.Hooks.PostRestore != nil {
			ht := createHookTemplate(kmapi.ObjectReference{
				Name:      meta_util.ValidNameWithPrefixNSuffix(oldRS.Name, "postrestore", "hook"),
				Namespace: oldRS.Namespace,
			}, oldRS.Spec.Hooks.PostRestore.Handler)
			if err := writeToTargetDir(ri.Filename, ht); err != nil {
				return err
			}
		}
	}
	return nil
}

func createRestoreSession(oldRS *v1beta1.RestoreSession, rt *resolvedTarget, encRef *kmapi.ObjectReference) *coreapi.RestoreSession {
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
			Target: configureTarget(oldRS.Namespace, ref, rt),
			DataSource: &coreapi.RestoreDataSource{
				Namespace:        namespace,
				Repository:       oldRS.Spec.Repository.Name,
				Snapshot:         setValidValue("Snapshot"),
				EncryptionSecret: encRef,
			},
			Addon:          configureRestoreAddonInfo(oldRS, rt),
			RestoreTimeout: oldRS.Spec.TimeOut,
			Hooks:          configureRestoreHooks(oldRS),
		},
	}
}

// restoreSessionComments builds the review line-comments for a converted RestoreSession.
func restoreSessionComments(encResolved bool) map[string]string {
	comments := map[string]string{
		"snapshot": "review: set the snapshot to restore (e.g. latest)",
	}
	if !encResolved {
		comments["encryptionSecret"] = "review: set via --encryption-secret-name / --encryption-secret-namespace"
	}
	return comments
}

func configureRestoreAddonInfo(rs *v1beta1.RestoreSession, rt *resolvedTarget) *coreapi.AddonInfo {
	var podTemplateSpec *ofst.PodTemplateSpec
	if rs.Spec.RuntimeSettings.Pod != nil {
		podTemplateSpec = &ofst.PodTemplateSpec{
			Spec: configurePodRuntimeSettings(rs.Spec.RuntimeSettings.Pod),
		}
	}
	if rt != nil {
		return &coreapi.AddonInfo{
			Name: rt.addonName,
			Tasks: []coreapi.TaskReference{
				{
					Name: apis.LogicalBackupRestore,
				},
			},
			ContainerRuntimeSettings: rs.Spec.RuntimeSettings.Container,
			JobTemplate:              podTemplateSpec,
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
