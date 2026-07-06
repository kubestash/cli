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
	store "kmodules.xyz/objectstore-api/api/v1"
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

	if secret := buildEncryptionSecret(repo.Name, repo.Namespace, repo.Spec.Backend.StorageSecretName); secret != nil {
		return writeToTargetDir(ri.Filename, secret)
	}
	return nil
}

// buildEncryptionSecret returns an encryption Secret carrying only the RESTIC_PASSWORD
// copied from the given storage Secret. It returns nil when the user supplies their own
// encryption Secret via flags, or when the RESTIC_PASSWORD cannot be read from the
// cluster (unreachable / missing / key absent) so callers keep placeholders.
func buildEncryptionSecret(name, namespace, storageSecretName string) *core.Secret {
	if encryptionSecretName != "" || encryptionSecretNamespace != "" {
		return nil
	}
	password, ok := resticPasswordFromStorageSecret(storageSecretName, namespace)
	if !ok {
		return nil
	}
	return &core.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: core.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      encryptionSecretNameFor(name),
			Namespace: namespace,
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
	return buildBackupStorage(repo.Name, repo.Namespace, repo.Spec)
}

// buildBackupStorage builds a KubeStash BackupStorage from a Stash RepositorySpec.
// It is shared by the Repository converter and the BackupBlueprint converter, whose
// spec inlines the same RepositorySpec (backend, wipeOut, usagePolicy).
func buildBackupStorage(name, namespace string, spec v1alpha1.RepositorySpec) *storageapi.BackupStorage {
	bs := &storageapi.BackupStorage{
		TypeMeta: metav1.TypeMeta{
			Kind:       storageapi.ResourceKindBackupStorage,
			APIVersion: storageapi.GroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}

	if spec.UsagePolicy != nil {
		bs.Spec.UsagePolicy = configureUsagePolicy(spec.UsagePolicy)
	}
	if spec.WipeOut {
		bs.Spec.DeletionPolicy = storageapi.DeletionPolicyWipeOut
	}

	configureStorageBackend(spec.Backend, bs)
	return bs
}

func configureStorageBackend(backend store.Backend, bs *storageapi.BackupStorage) {
	switch {
	case backend.S3 != nil:
		bs.Spec.Storage.Provider = storageapi.ProviderS3
		bs.Spec.Storage.S3 = &storageapi.S3Spec{
			Endpoint:   addConnectionScheme(backend.S3.Endpoint),
			Bucket:     backend.S3.Bucket,
			Prefix:     backend.S3.Prefix,
			Region:     backend.S3.Region,
			SecretName: backend.StorageSecretName,
		}
	case backend.GCS != nil:
		bs.Spec.Storage.Provider = storageapi.ProviderGCS
		bs.Spec.Storage.GCS = &storageapi.GCSSpec{
			Bucket:         backend.GCS.Bucket,
			Prefix:         backend.GCS.Prefix,
			MaxConnections: backend.GCS.MaxConnections,
			SecretName:     backend.StorageSecretName,
		}
	case backend.Azure != nil:
		bs.Spec.Storage.Provider = storageapi.ProviderAzure
		bs.Spec.Storage.Azure = &storageapi.AzureSpec{
			Container:      backend.Azure.Container,
			Prefix:         backend.Azure.Prefix,
			MaxConnections: backend.Azure.MaxConnections,
			StorageAccount: setValidValue("StorageAccount"),
		}
	case backend.Local != nil:
		bs.Spec.Storage.Provider = storageapi.ProviderLocal
		bs.Spec.Storage.Local = &storageapi.LocalSpec{
			// TODO: Configure VolumeSource
			MountPath: backend.Local.MountPath,
			SubPath:   backend.Local.SubPath,
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
	if err := writeToTargetDirWithComments(ri.Filename, newBC, repositoryComments(oldBC, rt, encResolved)); err != nil {
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

	// A KubeStash BackupBlueprint is namespaced, and it is co-located with the resources it
	// references: the BackupBlueprint, BackupStorage, RetentionPolicy and encryption Secret
	// all live in the same namespace. The old Stash BackupBlueprint is cluster-scoped, so we
	// derive that namespace from repoNamespace/backupNamespace and otherwise leave a single
	// placeholder for the operator to fill in consistently.
	ns := oldBB.Spec.RepoNamespace
	if ns == "" {
		ns = oldBB.Spec.BackupNamespace
	}
	if ns == "" {
		ns = oldBB.Namespace
	}
	if ns == "" {
		ns = setValidValue("Namespace")
	}

	// The Stash backend prefix mixed a static root with a per-target templated path. In
	// KubeStash the static root stays on the BackupStorage prefix, while the templated part
	// moves to the repository directory (the only place KubeStash resolves ${var} per-target).
	staticPrefix, templatedTail := splitPrefix(backendPrefix(oldBB.Spec.Backend))
	directory := translateStashPlaceholders(templatedTail)

	storageName := oldBB.Name + "-storage"
	encRef, encResolved := blueprintEncryptionSecretRef(oldBB.Name, ns, oldBB.Spec.Backend.StorageSecretName)

	newBB := createBackupBlueprint(oldBB, storageName, ns, directory, encRef)
	if err := writeToTargetDirWithComments(ri.Filename, newBB, blueprintComments(encResolved)); err != nil {
		return err
	}

	// BackupStorage (+ encryption Secret) generated from the blueprint's inline backend. The
	// prefix is left as a review placeholder (operators set the real storage root) with the
	// original Stash static prefix preserved as a trailing comment; the per-target templated
	// path already moved to the repository directory.
	storageSpec := oldBB.Spec.RepositorySpec
	storageSpec.Backend = backendWithPrefix(storageSpec.Backend, setValidValue("Prefix"))
	bs := buildBackupStorage(storageName, ns, storageSpec)
	if bs.Spec.DeletionPolicy == "" {
		bs.Spec.DeletionPolicy = storageapi.DeletionPolicyDelete
	}
	if err := writeToTargetDirWithComments(ri.Filename, bs, backupStorageComments(staticPrefix)); err != nil {
		return err
	}
	if secret := buildEncryptionSecret(oldBB.Name, ns, oldBB.Spec.Backend.StorageSecretName); secret != nil {
		if err := writeToTargetDir(ri.Filename, secret); err != nil {
			return err
		}
	}

	if oldBB.Spec.Hooks != nil {
		if oldBB.Spec.Hooks.PreBackup != nil {
			ht := createHookTemplate(kmapi.ObjectReference{
				Name:      meta_util.ValidNameWithPrefixNSuffix(oldBB.Name, "prebackup", "hook"),
				Namespace: ns,
			}, oldBB.Spec.Hooks.PreBackup)
			if err := writeToTargetDir(ri.Filename, ht); err != nil {
				return err
			}
		}

		if oldBB.Spec.Hooks.PostBackup != nil {
			ht := createHookTemplate(kmapi.ObjectReference{
				Name:      meta_util.ValidNameWithPrefixNSuffix(oldBB.Name, "postbackup", "hook"),
				Namespace: ns,
			}, oldBB.Spec.Hooks.PostBackup.Handler)
			if err := writeToTargetDir(ri.Filename, ht); err != nil {
				return err
			}
		}
	}

	rp := createRetentionPolicy(oldBB.Spec.RetentionPolicy, ns)
	if err := writeToTargetDir(ri.Filename, rp); err != nil {
		return err
	}

	return nil
}

func createBackupBlueprint(oldBB *v1beta1.BackupBlueprint, storageName, namespace, directory string, encRef *kmapi.ObjectReference) *coreapi.BackupBlueprint {
	spec := coreapi.BackupBlueprintSpec{
		// Subjects is intentionally left unset: it is optional, and KubeStash auto-backup
		// binds a blueprint to targets via blueprint.kubestash.com/* annotations on the
		// target (not via a subject list). See blueprint-migration.md.
		BackupConfigurationTemplate: &coreapi.BackupConfigurationTemplate{
			// The generated BackupConfiguration is created in the target's namespace, so the
			// template carries no namespace of its own. DeletionPolicy=OnDelete matches the
			// KubeStash auto-backup convention (delete the BackupConfiguration with the target).
			DeletionPolicy: coreapi.DeletionPolicyOnDelete,
			Backends:       []coreapi.BackendReference{configureBackendFromBlueprint(oldBB, storageName, namespace)},
			Sessions:       []coreapi.Session{configureSessionFromBlueprint(oldBB, namespace, directory, encRef)},
		},
	}
	if oldBB.Spec.UsagePolicy != nil {
		spec.UsagePolicy = configureUsagePolicy(oldBB.Spec.UsagePolicy)
	}
	return &coreapi.BackupBlueprint{
		TypeMeta: metav1.TypeMeta{
			Kind:       coreapi.ResourceKindBackupBlueprint,
			APIVersion: coreapi.GroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      oldBB.Name,
			Namespace: namespace,
		},
		Spec: spec,
	}
}

// blueprintEncryptionSecretRef mirrors encryptionSecretRef for BackupBlueprints, whose
// inline backend carries the storage Secret directly (there is no Repository to look up).
// CLI flags win; otherwise it references the Secret generated from the storage Secret's
// RESTIC_PASSWORD when present, else falls back to placeholders.
func blueprintEncryptionSecretRef(baseName, namespace, storageSecretName string) (*kmapi.ObjectReference, bool) {
	// The encryption Secret is co-located with the blueprint, so its namespace always tracks
	// the shared blueprint namespace; only the Secret name may remain a placeholder.
	if encryptionSecretName != "" || encryptionSecretNamespace != "" {
		name := encryptionSecretName
		if name == "" {
			name = setValidValue("Name")
		}
		ns := encryptionSecretNamespace
		if ns == "" {
			ns = namespace
		}
		return &kmapi.ObjectReference{Name: name, Namespace: ns}, encryptionSecretName != ""
	}

	if _, ok := resticPasswordFromStorageSecret(storageSecretName, namespace); ok {
		return &kmapi.ObjectReference{
			Name:      encryptionSecretNameFor(baseName),
			Namespace: namespace,
		}, true
	}
	return &kmapi.ObjectReference{
		Name:      setValidValue("Name"),
		Namespace: namespace,
	}, false
}

// backupStorageComments preserves the original Stash static prefix as a review comment on the
// generated BackupStorage prefix (which is emitted as a "### Set Valid Prefix ###" placeholder).
func backupStorageComments(originalPrefix string) map[string]string {
	if originalPrefix == "" {
		return nil
	}
	return map[string]string{"prefix": "review: set a valid prefix (Stash prefix: " + originalPrefix + ")"}
}

// blueprintComments builds the review line-comments attached to a converted BackupBlueprint.
func blueprintComments(encResolved bool) map[string]string {
	comments := map[string]string{
		"directory": "review: KubeStash resolves ${var} from variables.kubestash.com/<var> annotations on the target",
	}
	if !encResolved {
		comments["encryptionSecret"] = "review: set via --encryption-secret-name / --encryption-secret-namespace"
	}
	return comments
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

func configureBackendFromBlueprint(bb *v1beta1.BackupBlueprint, storageName, storageNS string) coreapi.BackendReference {
	return coreapi.BackendReference{
		Name: "storage",
		StorageRef: &kmapi.ObjectReference{
			Name:      storageName,
			Namespace: storageNS,
		},
		RetentionPolicy: &kmapi.ObjectReference{
			Name:      bb.Spec.RetentionPolicy.Name,
			Namespace: storageNS,
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
				Directory:        sessionDirectory(bc, rt),
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
// generated an encryption Secret for the given Stash Repository
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

// sessionDirectory derives the repository directory from the backup target
func sessionDirectory(bc *v1beta1.BackupConfiguration, rt *resolvedTarget) string {
	if rt != nil {
		return filepath.Join(rt.target.Namespace, rt.target.Name)
	}
	if bc.Spec.Target != nil && isTargetWorkload(bc.Spec.Target.Ref) {
		ns := bc.Namespace
		if bc.Spec.Target.Ref.Namespace != "" {
			ns = bc.Spec.Target.Ref.Namespace
		}
		return filepath.Join(ns, bc.Spec.Target.Ref.Name)
	}
	return setValidValue("Directory")
}

// directoryResolved reports whether sessionDirectory produced a real value (not a placeholder).
func directoryResolved(bc *v1beta1.BackupConfiguration, rt *resolvedTarget) bool {
	return rt != nil || (bc.Spec.Target != nil && isTargetWorkload(bc.Spec.Target.Ref))
}

// repositoryComments builds the review line-comments to attach to the generated YAML.
func repositoryComments(bc *v1beta1.BackupConfiguration, rt *resolvedTarget, encResolved bool) map[string]string {
	comments := map[string]string{}
	if directoryResolved(bc, rt) {
		comments["directory"] = "review: <namespace>/<name> of the backup target"
	}
	if !encResolved {
		comments["encryptionSecret"] = "review: set via --encryption-secret-name / --encryption-secret-namespace"
	}
	return comments
}

func configureSessionFromBlueprint(bb *v1beta1.BackupBlueprint, namespace, directory string, encRef *kmapi.ObjectReference) coreapi.Session {
	return coreapi.Session{
		SessionConfig: &coreapi.SessionConfig{
			Name:                "backup",
			SessionHistoryLimit: pointer.Int32(bb.Spec.BackupHistoryLimit),
			BackupTimeout:       bb.Spec.TimeOut,
			Hooks:               configureBackupHooks(bb.GetName(), namespace, bb.Spec.Hooks),
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
				Name:             `${repoName}`,
				Backend:          "storage",
				Directory:        directory,
				EncryptionSecret: encRef,
			},
		},
		Addon: configureBackupAddonInfoFromBlueprint(bb),
	}
}

// backendPrefix returns the prefix/subPath configured on the set provider of a Stash backend.
func backendPrefix(backend store.Backend) string {
	switch {
	case backend.S3 != nil:
		return backend.S3.Prefix
	case backend.GCS != nil:
		return backend.GCS.Prefix
	case backend.Azure != nil:
		return backend.Azure.Prefix
	case backend.Local != nil:
		return backend.Local.SubPath
	}
	return ""
}

// splitPrefix divides a Stash backend prefix into its static leading segments and the
// per-target templated tail (everything from the first ${...} placeholder onward). The
// static head stays on the BackupStorage prefix; the tail becomes the repository directory.
func splitPrefix(prefix string) (staticHead, templatedTail string) {
	idx := strings.Index(prefix, "${")
	if idx < 0 {
		return strings.Trim(prefix, "/"), ""
	}
	return strings.Trim(prefix[:idx], "/"), strings.Trim(prefix[idx:], "/")
}

// backendWithPrefix returns a copy of the backend with the set provider's prefix/subPath
// replaced. The provider struct is deep-copied so the caller's original backend is untouched.
func backendWithPrefix(backend store.Backend, prefix string) store.Backend {
	switch {
	case backend.S3 != nil:
		s3 := *backend.S3
		s3.Prefix = prefix
		backend.S3 = &s3
	case backend.GCS != nil:
		gcs := *backend.GCS
		gcs.Prefix = prefix
		backend.GCS = &gcs
	case backend.Azure != nil:
		azure := *backend.Azure
		azure.Prefix = prefix
		backend.Azure = &azure
	case backend.Local != nil:
		local := *backend.Local
		local.SubPath = prefix
		backend.Local = &local
	}
	return backend
}

// stashPlaceholderReplacer maps old Stash reserved backend-prefix placeholders to the
// KubeStash custom-variable convention. In KubeStash these ${var} names are resolved from
// variables.kubestash.com/<var> annotations on the target application at apply time.
var stashPlaceholderReplacer = strings.NewReplacer(
	"${TARGET_NAMESPACE}", "${namespace}",
	"${TARGET_NAME}", "${targetName}",
	"${TARGET_KIND}", "${targetKind}",
	"${TARGET_APP_RESOURCE}", "${dbType}",
	"${TARGET_APP_VERSION}", "${appVersion}",
)

func translateStashPlaceholders(s string) string {
	return stashPlaceholderReplacer.Replace(s)
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
				Namespace: configNs,
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

	// An empty Stash task means a KubeDB database blueprint: its KubeStash task is the standard
	// "logical-backup" (matching the auto-backup guide). When the old blueprint names a Task
	// (non-KubeDB target), carry its name and params instead. The addon name itself has no
	// reliable analogue in Stash and depends on the DB type, so it stays a descriptive placeholder.
	task := coreapi.TaskReference{Name: apis.LogicalBackup}
	if bb.Spec.Task.Name != "" {
		task = coreapi.TaskReference{
			Name:   bb.Spec.Task.Name,
			Params: taskParamsToRawExtension(bb.Spec.Task.Params),
		}
	}

	return &coreapi.AddonInfo{
		Name:                     setValidValue("Addon Name (e.g. postgres-addon)"),
		Tasks:                    []coreapi.TaskReference{task},
		ContainerRuntimeSettings: bb.Spec.RuntimeSettings.Container,
		JobTemplate:              podTemplateSpec,
	}
}

// taskParamsToRawExtension converts Stash task params (name/value pairs) into the free-form
// RawExtension object KubeStash task references use.
func taskParamsToRawExtension(params []v1beta1.Param) *runtime.RawExtension {
	if len(params) == 0 {
		return nil
	}
	m := make(map[string]any, len(params))
	for _, p := range params {
		m[p.Name] = p.Value
	}
	data, err := json.Marshal(m)
	if err != nil {
		return nil
	}
	return &runtime.RawExtension{Raw: data}
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
