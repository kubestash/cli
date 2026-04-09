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

package cloud

import (
	"context"
	"fmt"
	"maps"
	"sort"

	"kubestash.dev/apimachinery/apis"
	"kubestash.dev/apimachinery/apis/core/v1alpha1"
	storageapi "kubestash.dev/apimachinery/apis/storage/v1alpha1"

	batchv1 "k8s.io/api/batch/v1"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kmapi "kmodules.xyz/client-go/api/v1"
	kmc "kmodules.xyz/client-go/client"
	"kmodules.xyz/client-go/meta"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	AWSSeedRoleAnnotationName        = "go.klusters.dev/seed-role-name"
	AWSIRSARoleAnnotation            = "eks.amazonaws.com/role-arn"
	GCPWorkloadIdentityAnnotationKey = "go.klusters.dev/iam-gke-io-workloadIdentity"
	BucketAnnotationKey              = "go.klusters.dev/bucket-names"
	GCPClusterNameAnnotationKey      = "go.klusters.dev/iam-gke-cluster-name"
	GCPClusterRegionAnnotationKey    = "go.klusters.dev/iam-gke-cluster-region"
	GCPProjectIDAnnotationKey        = "go.klusters.dev/iam-gke-project-id"
	GCPProjectNumberAnnotationKey    = "go.klusters.dev/iam-gke-project-number"
	GCPRolesAnnotationKey            = "go.klusters.dev/iam-gke-roles"

	AzureMINameAnnotation         = "klusters.dev/azure-mi-name"
	AzureResourceGroupAnnotation  = "klusters.dev/azure-rg-name"
	AzureSubscriptionIDAnnotation = "klusters.dev/azure-subscription-id"
	AzureMIClientIDAnnotation     = "azure.workload.identity/client-id"
	AzureMITenantIDAnnotation     = "azure.workload.identity/tenant-id"
)

func GetCloudAnnotations(ctx context.Context, kc client.Client, storages ...storageapi.BackupStorage) (map[string]string, error) {
	annotations, err := GetCloudAnnotationsFromServiceAccount(ctx, kc)
	if err != nil {
		return nil, err
	}
	if storages != nil {
		setBucketAnnotations(annotations, storages...)
	}
	return annotations, nil
}

func GetCloudAnnotationsFromServiceAccount(ctx context.Context, kc client.Client) (map[string]string, error) {
	sa, err := getServiceAccount(ctx, kc, &kmapi.ObjectReference{
		Name:      meta.PodServiceAccount(),
		Namespace: meta.PodNamespace(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve service account: %w", err)
	}
	annotations := map[string]string{}
	if val, ok := sa.Annotations[AWSIRSARoleAnnotation]; ok {
		annotations[AWSSeedRoleAnnotationName] = val
	}
	if val, ok := sa.Annotations[GCPWorkloadIdentityAnnotationKey]; ok {
		annotations[GCPWorkloadIdentityAnnotationKey] = val
	}
	if val, ok := sa.Annotations[GCPClusterNameAnnotationKey]; ok {
		annotations[GCPClusterNameAnnotationKey] = val
	}
	if val, ok := sa.Annotations[GCPClusterRegionAnnotationKey]; ok {
		annotations[GCPClusterRegionAnnotationKey] = val
	}
	if val, ok := sa.Annotations[GCPProjectIDAnnotationKey]; ok {
		annotations[GCPProjectIDAnnotationKey] = val
	}
	if val, ok := sa.Annotations[GCPProjectNumberAnnotationKey]; ok {
		annotations[GCPProjectNumberAnnotationKey] = val
	}
	if val, ok := sa.Annotations[GCPRolesAnnotationKey]; ok {
		annotations[GCPRolesAnnotationKey] = val
	}
	if val, ok := sa.Annotations[AzureMINameAnnotation]; ok {
		annotations[AzureMINameAnnotation] = val
	}
	if val, ok := sa.Annotations[AzureResourceGroupAnnotation]; ok {
		annotations[AzureResourceGroupAnnotation] = val
	}
	if val, ok := sa.Annotations[AzureSubscriptionIDAnnotation]; ok {
		annotations[AzureSubscriptionIDAnnotation] = val
	}
	return annotations, nil
}

func getServiceAccount(ctx context.Context, c client.Client, ref *kmapi.ObjectReference) (*core.ServiceAccount, error) {
	sa := &core.ServiceAccount{}
	if err := c.Get(ctx, ref.ObjectKey(), sa); err != nil {
		return nil, err
	}
	return sa, nil
}

func setBucketAnnotations(annotations map[string]string, storages ...storageapi.BackupStorage) {
	if !meta.HasKey(annotations, AWSSeedRoleAnnotationName) && !meta.HasKey(annotations, GCPWorkloadIdentityAnnotationKey) &&
		!meta.HasKey(annotations, AzureSubscriptionIDAnnotation) {
		return
	}

	bucketNames := ""
	for _, backupStorage := range storages {
		switch backupStorage.Spec.Storage.Provider {
		case storageapi.ProviderS3:
			bucketNames = fmt.Sprintf("%s,%s", bucketNames, backupStorage.Spec.Storage.S3.Bucket)
		case storageapi.ProviderGCS:
			bucketNames = fmt.Sprintf("%s,%s", bucketNames, backupStorage.Spec.Storage.GCS.Bucket)
		case storageapi.ProviderAzure:
			bucketNames = fmt.Sprintf("%s#%s,%s", bucketNames,
				backupStorage.Spec.Storage.Azure.Container, backupStorage.Spec.Storage.Azure.StorageAccount) // format "container1,storageaccount1#container2,storageaccount2#..."
		}
	}
	if bucketNames != "" {
		annotations[BucketAnnotationKey] = bucketNames[1:]
	}
}

func AddCloudAnnotationsToSAIfNeeded(ctx context.Context, kbClient client.Client,
	bs *storageapi.BackupStorage, saRef *kmapi.ObjectReference, bcRef *kmapi.ObjectReference,
) (bool, error) {
	sa, err := getServiceAccount(ctx, kbClient, saRef)
	if err != nil {
		return true, fmt.Errorf("failed to get service account: %v", err)
	}
	if !isCloudAnnotationNeeded(bs, sa) { // Return if not needed
		return false, nil
	}
	if err := addAnnotationsToServiceAccount(ctx, kbClient, bs, sa, bcRef); err != nil {
		return true, fmt.Errorf("failed to add cloud annotations to database service account: %w", err)
	}
	if !hasCredLessManagerProvidedAnnotation(bs, sa) {
		return true, nil
	}

	return false, nil
}

func hasCredLessManagerProvidedAnnotation(bs *storageapi.BackupStorage, sa *core.ServiceAccount) bool {
	switch bs.Spec.Storage.Provider {
	case storageapi.ProviderS3:
		_, exists := sa.Annotations[AWSIRSARoleAnnotation]
		return exists
	default:
		return false
	}
}

func isCloudAnnotationNeeded(bs *storageapi.BackupStorage, sa *core.ServiceAccount) bool {
	if bs.IsCredentialLessModeEnabled() {
		switch bs.Spec.Storage.Provider {
		case storageapi.ProviderS3:
			_, ok := sa.Annotations[AWSSeedRoleAnnotationName]
			return !ok
			// case storageapi.ProviderAzure:
		}
	}
	return false
}

func addAnnotationsToServiceAccount(ctx context.Context, kbClient client.Client, bs *storageapi.BackupStorage, sa *core.ServiceAccount, bcRef *kmapi.ObjectReference) error {
	if hasRequiredCloudAnnotations(bs, sa) {
		return nil
	}

	saAnnotations, err := getLatestBackupSAAnnotations(ctx, kbClient, bcRef)
	if err != nil {
		return fmt.Errorf("failed to fetch annotations from latest successful backup: %w", err)
	}
	reqAnnotations, err := getRequiredAnnotations(bs, saAnnotations)
	if err != nil {
		return fmt.Errorf("failed to annotate required cloud annotations: %w", err)
	}
	_, err = kmc.Patch(ctx, kbClient, sa, func(obj client.Object) client.Object {
		in := obj.(*core.ServiceAccount)
		if in.Annotations == nil {
			in.Annotations = make(map[string]string)
		}
		maps.Copy(in.Annotations, reqAnnotations)
		return in
	})
	if err != nil {
		return fmt.Errorf("failed to update service account %s/%s with cloud annotations: %w",
			sa.Namespace, sa.Name, err)
	}
	return nil
}

func hasRequiredCloudAnnotations(bs *storageapi.BackupStorage, sa *core.ServiceAccount) bool {
	if bs.Spec.Storage.Provider == storageapi.ProviderS3 {
		return sa.Annotations[AWSSeedRoleAnnotationName] != "" && sa.Annotations[BucketAnnotationKey] != ""
	}
	return false
}

func getLatestBackupSAAnnotations(ctx context.Context, kbClient client.Client, bcRef *kmapi.ObjectReference) (map[string]string, error) {
	session, err := findLatestSuccessfulBackupSession(ctx, kbClient, bcRef)
	if err != nil {
		return nil, err
	}
	job, err := getBackupJobFromSession(ctx, kbClient, session)
	if err != nil {
		return nil, err
	}
	sa, err := getSAFromJob(ctx, kbClient, job)
	if err != nil {
		return nil, err
	}
	return sa.Annotations, nil
}

func getSAFromJob(ctx context.Context, kbClient client.Client, job *batchv1.Job) (*core.ServiceAccount, error) {
	sa := &core.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: job.Namespace,
			Name:      job.Spec.Template.Spec.ServiceAccountName,
		},
	}
	if err := kbClient.Get(ctx, client.ObjectKeyFromObject(sa), sa); err != nil {
		return nil, fmt.Errorf("failed to get service account %s/%s: %w", sa.Namespace, sa.Name, err)
	}
	return sa, nil
}

func findLatestSuccessfulBackupSession(ctx context.Context, kbClient client.Client, bcRef *kmapi.ObjectReference) (*v1alpha1.BackupSession, error) {
	list := &v1alpha1.BackupSessionList{}
	opts := []client.ListOption{
		client.MatchingLabels{apis.KubeStashInvokerName: bcRef.Name},
		client.InNamespace(bcRef.Namespace),
	}
	if err := kbClient.List(ctx, list, opts...); err != nil {
		return nil, fmt.Errorf("failed to list backup sessions for %s/%s: %w",
			bcRef.Namespace, bcRef.Name, err)
	}

	// Sort by creation timestamp descending (newest first)
	sort.Slice(list.Items, func(i, j int) bool {
		return list.Items[i].CreationTimestamp.After(list.Items[j].CreationTimestamp.Time)
	})

	for i := range list.Items {
		session := &list.Items[i]
		if session.Spec.Session == apis.SessionFullBackup &&
			session.Status.Phase == v1alpha1.BackupSessionSucceeded {
			return session, nil
		}
	}
	return nil, fmt.Errorf("no successful backup session found for configuration %s/%s",
		bcRef.Namespace, bcRef.Name)
}

func getBackupJobFromSession(ctx context.Context, kbClient client.Client, session *v1alpha1.BackupSession) (*batchv1.Job, error) {
	list := &batchv1.JobList{}
	opts := []client.ListOption{
		client.MatchingLabels{
			apis.KubeStashSessionName:      apis.SessionFullBackup,
			meta.ComponentLabelKey:         apis.KubeStashBackupComponent,
			apis.KubeStashInvokerName:      session.Name,
			apis.KubeStashInvokerNamespace: session.Namespace,
		},
		client.InNamespace(session.Namespace),
	}
	if err := kbClient.List(ctx, list, opts...); err != nil {
		return nil, fmt.Errorf("failed to list backup jobs for session %s/%s: %w",
			session.Namespace, session.Name, err)
	}

	if len(list.Items) == 0 {
		return nil, fmt.Errorf("no backup jobs found for session %s/%s",
			session.Namespace, session.Name)
	}
	return &list.Items[0], nil
}

func getAWSAnnotations(source map[string]string) (map[string]string, error) {
	required := map[string]string{
		AWSSeedRoleAnnotationName: source[AWSSeedRoleAnnotationName],
		BucketAnnotationKey:       source[BucketAnnotationKey],
	}
	annotations := make(map[string]string)
	for key, val := range required {
		annotations[key] = val
	}
	return annotations, nil
}

func getRequiredAnnotations(bs *storageapi.BackupStorage, annotations map[string]string) (map[string]string, error) {
	switch bs.Spec.Storage.Provider {
	case storageapi.ProviderS3:
		return getAWSAnnotations(annotations)
	// case storageapi.ProviderGCS:
	// 	return applyGCPAnnotations(sa, annotations)
	default:
		return nil, fmt.Errorf("unsupported storage provider: %s", bs.Spec.Storage.Provider)

	}
}
