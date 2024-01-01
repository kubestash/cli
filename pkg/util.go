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
	"bytes"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	vsapi "github.com/kubernetes-csi/external-snapshotter/client/v4/apis/volumesnapshot/v1"
	"github.com/olekukonko/tablewriter"
	"gomodules.xyz/go-sh"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/klog/v2"
	"k8s.io/kubectl/pkg/scheme"
	kmapi "kmodules.xyz/client-go/api/v1"
	kmc "kmodules.xyz/client-go/client"
	meta_util "kmodules.xyz/client-go/meta"
	"kubestash.dev/apimachinery/apis"
	configapi "kubestash.dev/apimachinery/apis/config/v1alpha1"
	coreapi "kubestash.dev/apimachinery/apis/core/v1alpha1"
	storageapi "kubestash.dev/apimachinery/apis/storage/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	klient client.Client

	dstNamespace string
	srcNamespace string

	imgRestic configapi.Docker
)

func init() {
	imgRestic.Registry = ResticRegistry
	imgRestic.Image = ResticImage
	imgRestic.Tag = ResticTag
}

func getSecret(ref kmapi.ObjectReference) (*core.Secret, error) {
	secret := &core.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ref.Name,
			Namespace: ref.Namespace,
		},
	}

	if err := klient.Get(context.Background(), client.ObjectKeyFromObject(secret), secret); err != nil {
		return nil, err
	}

	return secret, nil
}

func getServiceAccount(ref kmapi.ObjectReference) (*core.ServiceAccount, error) {
	sa := &core.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ref.Name,
			Namespace: ref.Namespace,
		},
	}

	if err := klient.Get(context.Background(), client.ObjectKeyFromObject(sa), sa); err != nil {
		return nil, err
	}

	return sa, nil
}

func getPVC(ref kmapi.ObjectReference) (*core.PersistentVolumeClaim, error) {
	pvc := &core.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ref.Name,
			Namespace: ref.Namespace,
		},
	}

	if err := klient.Get(context.Background(), client.ObjectKeyFromObject(pvc), pvc); err != nil {
		return nil, err
	}

	return pvc, nil
}

func getVolumeSnapshot(ref kmapi.ObjectReference) (*vsapi.VolumeSnapshot, error) {
	volumeSnapshot := &vsapi.VolumeSnapshot{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ref.Name,
			Namespace: ref.Namespace,
		},
	}

	if err := klient.Get(context.Background(), client.ObjectKeyFromObject(volumeSnapshot), volumeSnapshot); err != nil {
		return nil, err
	}

	return volumeSnapshot, nil
}

func getBackupStorage(ref kmapi.ObjectReference) (*storageapi.BackupStorage, error) {
	storage := &storageapi.BackupStorage{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ref.Name,
			Namespace: ref.Namespace,
		},
	}

	if err := klient.Get(context.Background(), client.ObjectKeyFromObject(storage), storage); err != nil {
		return nil, err
	}

	return storage, nil
}

func getRepository(ref kmapi.ObjectReference) (*storageapi.Repository, error) {
	repo := &storageapi.Repository{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ref.Name,
			Namespace: ref.Namespace,
		},
	}

	if err := klient.Get(context.Background(), client.ObjectKeyFromObject(repo), repo); err != nil {
		return nil, err
	}

	return repo, nil
}

func getSnapshot(ref kmapi.ObjectReference) (*storageapi.Snapshot, error) {
	snap := &storageapi.Snapshot{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ref.Name,
			Namespace: ref.Namespace,
		},
	}

	if err := klient.Get(context.Background(), client.ObjectKeyFromObject(snap), snap); err != nil {
		return nil, err
	}

	return snap, nil
}

func getBackupConfiguration(ref kmapi.ObjectReference) (*coreapi.BackupConfiguration, error) {
	bc := &coreapi.BackupConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ref.Name,
			Namespace: ref.Namespace,
		},
	}

	if err := klient.Get(context.Background(), client.ObjectKeyFromObject(bc), bc); err != nil {
		return nil, err
	}

	return bc, nil
}

func getRestoreSession(ref kmapi.ObjectReference) (*coreapi.RestoreSession, error) {
	rs := &coreapi.RestoreSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ref.Name,
			Namespace: ref.Namespace,
		},
	}

	if err := klient.Get(context.Background(), client.ObjectKeyFromObject(rs), rs); err != nil {
		return nil, err
	}

	return rs, nil
}

func setBackupConfigurationPausedField(value bool, name string) error {
	backupConfig, err := getBackupConfiguration(kmapi.ObjectReference{
		Name:      name,
		Namespace: srcNamespace,
	})
	if err != nil {
		return err
	}

	_, err = kmc.CreateOrPatch(
		context.Background(),
		klient,
		backupConfig,
		func(obj client.Object, createOp bool) client.Object {
			in := obj.(*coreapi.BackupConfiguration)
			in.Spec.Paused = value
			return in
		},
	)
	return err
}

func createTable(data [][]string) error {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Item", "Reason"})
	table.SetAutoMergeCells(true)
	table.SetRowLine(true)
	table.AppendBulk(data)
	table.Render()

	_, err := fmt.Fprintf(os.Stdout, "\n\n")
	if err != nil {
		return err
	}
	return nil
}

func showLogs(pod core.Pod, args ...string) error {
	_, err := fmt.Fprintf(os.Stdout, "==================[ Logs from pod: %s/%s ]==================\n", pod.Namespace, pod.Name)
	if err != nil {
		return err
	}
	cmdArgs := []string{"logs", "-n", pod.Namespace, pod.Name}
	cmdArgs = append(cmdArgs, args...)
	return sh.Command(CmdKubectl, cmdArgs).Run()
}

func getOperatorPod() (core.Pod, error) {
	var podList core.PodList

	// TODO: change the labels?
	sel, err := metav1.LabelSelectorAsSelector(&metav1.LabelSelector{
		MatchLabels: map[string]string{
			meta_util.NameLabelKey: "kubestash-operator",
		},
	})
	if err != nil {
		return core.Pod{}, err
	}

	opts := client.ListOption(client.MatchingLabelsSelector{Selector: sel})
	if err := klient.List(context.Background(), &podList, opts); err != nil {
		return core.Pod{}, err
	}

	for i := range podList.Items {
		if hasKubeStashOperatorContainer(&podList.Items[i]) {
			return podList.Items[i], nil
		}
	}

	return core.Pod{}, fmt.Errorf("operator pod not found")
}

func hasKubeStashOperatorContainer(pod *core.Pod) bool {
	if strings.Contains(pod.Name, "kubestash") {
		for _, c := range pod.Spec.Containers {
			if c.Name == apis.OperatorContainer {
				return true
			}
		}
	}
	return false
}

func getLocalBackendAccessorPod(obj kmapi.ObjectReference) (*core.Pod, error) {
	var pods core.PodList
	appLabels := map[string]string{
		apis.KubeStashApp: apis.KubeStashNetVolAccessor,
	}
	opts := []client.ListOption{client.InNamespace(obj.Namespace), client.MatchingLabels(appLabels)}
	if err := klient.List(context.Background(), &pods, opts...); err != nil {
		return nil, err
	}

	for i := range pods.Items {
		if hasVolume(pods.Items[i].Spec.Volumes, obj.Name) {
			for _, c := range pods.Items[i].Spec.Containers {
				if hasVolumeMount(c.VolumeMounts, obj.Name) {
					return &pods.Items[i], nil
				}
			}
		}
	}

	return nil, fmt.Errorf("no local backend accessor pod found for BackupStorage: %s/%s", obj.Namespace, obj.Name)
}

func hasVolume(volumes []core.Volume, name string) bool {
	for i := range volumes {
		if volumes[i].Name == name {
			return true
		}
	}
	return false
}

func hasVolumeMount(mounts []core.VolumeMount, name string) bool {
	for i := range mounts {
		if mounts[i].Name == name {
			return true
		}
	}
	return false
}

func isWorkloadIdentity(pod core.Pod) (bool, error) {
	azureLabel := "azure.workload.identity/use"
	googleAnnotation := "iam.gke.io/gcp-service-account"
	awsAnnotation := "eks.amazonaws.com/role-arn"

	if value, exists := pod.Labels[azureLabel]; exists {
		boolValue, err := strconv.ParseBool(value)
		if err != nil {
			return false, err
		}
		return boolValue, nil
	}

	sa, err := getServiceAccount(kmapi.ObjectReference{
		Name:      pod.Spec.ServiceAccountName,
		Namespace: pod.Namespace,
	})
	if err != nil {
		return false, err
	}

	if _, exists := sa.Annotations[googleAnnotation]; exists {
		return true, nil
	} else if _, exists := sa.Annotations[awsAnnotation]; exists {
		return true, nil
	}

	return false, nil
}

func execOnPod(config *rest.Config, pod *core.Pod, command []string) (string, error) {
	var (
		execOut bytes.Buffer
		execErr bytes.Buffer
	)

	klog.Infof("Executing command %v on pod %s/%s", command, pod.Namespace, pod.Name)

	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return "", err
	}

	req := kubeClient.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(pod.Name).
		Namespace(pod.Namespace).
		SubResource("exec").
		Timeout(5 * time.Minute)
	req.VersionedParams(&core.PodExecOptions{
		Container: getContainerName(pod),
		Command:   command,
		Stdout:    true,
		Stderr:    true,
	}, scheme.ParameterCodec)

	executor, err := remotecommand.NewSPDYExecutor(config, "POST", req.URL())
	if err != nil {
		return "", fmt.Errorf("failed to init executor: %v", err)
	}

	err = executor.StreamWithContext(context.Background(), remotecommand.StreamOptions{
		Stdout: &execOut,
		Stderr: &execErr,
		Tty:    true,
	})

	if err != nil {
		return "", fmt.Errorf("could not execute: %v, reason: %s", err, execErr.String())
	}

	return execOut.String(), nil
}

func getContainerName(pod *core.Pod) string {
	if hasKubeStashOperatorContainer(pod) {
		return apis.OperatorContainer
	}
	return apis.KubeStashContainer
}
