package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aerokube/selenoid/config"
	"github.com/aerokube/selenoid/session"
	"github.com/aerokube/util"
	"golang.org/x/net/websocket"
	apiv1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	k8sJson "k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/client-go/kubernetes"
	k8s_config "sigs.k8s.io/controller-runtime/pkg/client/config"
)

const (
	selenium         int32  = 4444
	fileserver       int32  = 8080
	clipboard        int32  = 9090
	vnc              int32  = 5900
	devtools         int32  = 7070
	sizeLimitDefault string = "256Mi"
)

// Kubernetes pod
type Kubernetes struct {
	ServiceBase
	Environment
	session.Caps
}

func sanitizeStringAsValidDNSLabel(s string) string {
	pref := regexp.MustCompile("[^a-zA-Z0-9]+")
	s = pref.ReplaceAllString(s, "-")
	return s
}

func yamlifyObject(o runtime.Object) string {
	k8sObjYamlSerializer := k8sJson.NewSerializerWithOptions(
		k8sJson.DefaultMetaFactory, nil, nil,
		k8sJson.SerializerOptions{
			Yaml:   true,
			Pretty: true,
		},
	)
	var buf bytes.Buffer
	_ = k8sObjYamlSerializer.Encode(o, &buf)
	return buf.String()
}

func jsonifyObject(o runtime.Object, pretty bool) string {
	k8sObjJsonSerializer := k8sJson.NewSerializerWithOptions(
		k8sJson.DefaultMetaFactory, nil, nil,
		k8sJson.SerializerOptions{
			Yaml:   true,
			Pretty: pretty,
		},
	)
	var buf bytes.Buffer
	_ = k8sObjJsonSerializer.Encode(o, &buf)
	return buf.String()
}

func getK8sClient() (*kubernetes.Clientset, error) {
	config, err := k8s_config.GetConfigWithContext(os.Getenv("KUBECONFIG_CONTEXT"))
	if err != nil {
		return nil, fmt.Errorf("failed to get k8s cluster config: %v", err)
	}
	k8sClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create k8s client: %v", err)
	}
	return k8sClient, nil
}

// StartWithCancel - Starter interface implementation
func (k *Kubernetes) StartWithCancel() (*StartedService, error) {
	k8sClient, err := getK8sClient()
	if err != nil {
		return nil, err
	}
	requestID := k.RequestId
	image := k.Service.Image.(string)
	namespace := k.Environment.OrchestratorOptions["k8sNamespace"]
	containerName := sanitizeStringAsValidDNSLabel(image)

	volumes := []apiv1.Volume{
		{
			Name: "shm",
			VolumeSource: apiv1.VolumeSource{
				EmptyDir: &apiv1.EmptyDirVolumeSource{
					Medium:    apiv1.StorageMediumMemory,
					SizeLimit: getEmptyDirSizeLimit(k.Service),
				},
			},
		},
	}
	volumeMounts := []apiv1.VolumeMount{
		{Name: "shm", MountPath: "/dev/shm"},
	}
	for i, v := range k.Service.Volumes {
		var vs apiv1.VolumeSource
		splits := strings.SplitN(v, "=", 2)
		if len(splits) != 2 {
			return nil, fmt.Errorf("failed to parse volumes: invalid format")
		}
		err = json.Unmarshal([]byte(splits[1]), &vs)
		if err != nil {
			return nil, fmt.Errorf("failed to parse volumes: %w", err)
		}
		volumes = append(volumes, apiv1.Volume{
			Name:         fmt.Sprintf("vol%d", i),
			VolumeSource: vs,
		})
		volumeMounts = append(volumeMounts, apiv1.VolumeMount{
			Name:      fmt.Sprintf("vol%d", i),
			MountPath: splits[0],
		})
	}

	v1Pod := &apiv1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: containerName + "-",
			Namespace:    namespace,
			Labels:       k.getMetadataLabels(),
		},
		Spec: apiv1.PodSpec{
			Containers: []apiv1.Container{
				{
					Name:  "browser",
					Image: image,
					Env:   getEnvVars(k.ServiceBase, k.Caps),

					Resources:    getResources(k.ServiceBase),
					Ports:        getContainerPort(),
					VolumeMounts: volumeMounts,
					SecurityContext: &apiv1.SecurityContext{
						Privileged: &k.Privileged,
					},
				},
			},
			SecurityContext: &apiv1.PodSecurityContext{
				Sysctls: getSysCtl(k.Service.Sysctl),
			},
			Volumes:       volumes,
			Hostname:      k.Caps.ContainerHostname,
			HostAliases:   getHostAliases(k.Service),
			RestartPolicy: apiv1.RestartPolicyNever,
		},
	}

	if k.Caps.ContainerName != "" { // use provided name for both pod and container
		containerName := sanitizeStringAsValidDNSLabel(k.Caps.ContainerName)
		v1Pod.ObjectMeta.GenerateName = ""
		v1Pod.ObjectMeta.Name = containerName
		v1Pod.Spec.Containers[0].Name = containerName
	}

	if len(k.Caps.DNSServers) > 0 {
		v1Pod.Spec.DNSConfig = &apiv1.PodDNSConfig{
			Nameservers: k.Caps.DNSServers,
		}
	}

	k8sPodSpecExtraOptions := k.Environment.OrchestratorOptions["k8sPodSpecExtraOptions"]
	if k8sPodSpecExtraOptions != "" {
		if json.Unmarshal([]byte(k8sPodSpecExtraOptions), &v1Pod.Spec) != nil {
			return nil, fmt.Errorf("failed to parse k8sPodSpecExtraOptions: %v | %w", k8sPodSpecExtraOptions, err)
		}
	}

	// podYaml, _ := yaml.Marshal(v1Pod)
	log.Printf("[%d] [CREATING_POD] [%s] [%s] Pod=%s", requestID, image, namespace, jsonifyObject(v1Pod, false))

	podStartTime := time.Now()
	podObj, err := k8sClient.CoreV1().Pods(namespace).Create(context.Background(), v1Pod, metav1.CreateOptions{})
	podName := podObj.GetName()
	if err != nil {
		deletePod(podName, namespace, k8sClient, requestID)
		return nil, fmt.Errorf("start pod: %v", err)
	}

	if err := waitForPodToBeReady(k8sClient, namespace, podName, k.StartupTimeout); err != nil {
		deletePod(podName, namespace, k8sClient, requestID)
		return nil, fmt.Errorf("status pod: %v", err)
	}

	log.Printf("[%d] [POD_CREATED] [%s] [%s] [%.2fs]", requestID, podName, image, util.SecondsSince(podStartTime))

	podIP := getPodIP(podName, namespace, k8sClient)
	hostPort := buildHostPort(podIP, k.Caps)

	u := &url.URL{Scheme: "http", Host: hostPort.Selenium, Path: k.Service.Path}

	log.Printf("[%d] [POD_URL] [%s] [%s]", requestID, podName, u.String())

	if err := wait(u.String(), k.StartupTimeout); err != nil {
		deletePod(podName, namespace, k8sClient, requestID)
	}

	s := StartedService{
		Url: u,
		Pod: &session.Pod{
			ID:            string(podObj.GetUID()),
			IPAddress:     podIP,
			Name:          podObj.GetName(),
			ContainerName: containerName,
			Namespace:     namespace,
		},
		HostPort: session.HostPort{
			Selenium:   hostPort.Selenium,
			Fileserver: hostPort.Fileserver,
			Clipboard:  hostPort.Clipboard,
			VNC:        hostPort.VNC,
			Devtools:   hostPort.Devtools,
		},
		Cancel: func() {
			defer deletePod(podName, namespace, k8sClient, requestID)
		},
	}
	return &s, nil
}

func (k *Kubernetes) getMetadataLabels() map[string]string {
	labels := getLabels(k.Service, k.Caps)
	for k, v := range labels {
		labels[k] = sanitizeStringAsValidDNSLabel(v)
	}
	return labels
}

func deletePod(name string, ns string, k8sClient *kubernetes.Clientset, requestID uint64) {
	log.Printf("[%d] [DELETING_POD] [%s] [%s]", requestID, name, ns)
	deletePolicy := metav1.DeletePropagationForeground
	err := k8sClient.CoreV1().Pods(ns).Delete(context.Background(), name, metav1.DeleteOptions{
		PropagationPolicy: &deletePolicy,
	})
	if err != nil {
		log.Printf("delete pod: %v", err)
		return
	}
	log.Printf("[%d] [POD_DELETED] [%s] [%s]", requestID, name, ns)
}

func getPodIP(name string, ns string, k8sClient *kubernetes.Clientset) string {
	ip := ""
	pods, err := k8sClient.CoreV1().Pods(ns).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		fmt.Printf("pods list: %v", err)
	}
	for _, pod := range pods.Items {
		if pod.Name == name {
			ip = pod.Status.PodIP
		}
	}
	return ip
}

func buildHostPort(ip string, caps session.Caps) session.HostPort {
	fn := func(ip string, servicePort int32) string {
		port := strconv.Itoa(int(servicePort))
		return net.JoinHostPort(ip, port)
	}
	hp := session.HostPort{
		Selenium:   fn(ip, selenium),
		Fileserver: fn(ip, fileserver),
		Clipboard:  fn(ip, clipboard),
		Devtools:   fn(ip, devtools),
	}

	if caps.VNC {
		hp.VNC = fn(ip, vnc)
	}

	return hp
}

func waitForPodToBeReady(k8sClient *kubernetes.Clientset, namespace, podName string, timeout time.Duration) error {

	ctx := context.Background()
	podObj, err := k8sClient.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	status := podObj.Status

	w, err := k8sClient.CoreV1().Pods(namespace).Watch(ctx, metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector("metadata.name", podName).String(),
	})
	if err != nil {
		return err
	}
	if podObj.Status.Phase == apiv1.PodPending {
		startedAt := time.Now()
		func() {
			for {
				select {
				case ev, ok := <-w.ResultChan():
					if !ok {
						return
					}
					if podObj, ok := ev.Object.(*apiv1.Pod); ok {
						status = podObj.Status
						if podObj.Status.Phase != apiv1.PodPending {
							w.Stop()
						}
					} else {
						log.Printf("[UNHANDLED EVENT] [Pod=%s] [%s] Obj=\n%s", podName, ev.Type, yamlifyObject(ev.Object))
					}
				case <-time.After(timeout):
					w.Stop()
				case <-time.NewTicker(3 * time.Second).C:
					log.Printf("[WAITING FOR POD] [Pod=%s] [%s] [%s]", podName, status.Phase, time.Since(startedAt).Truncate(time.Second).String())
				}
			}
		}()
	}
	if status.Phase != apiv1.PodRunning {
		return fmt.Errorf("Pod is unavailable: %v", status.Phase)
	}
	return nil
}

func getEnvVars(service ServiceBase, caps session.Caps) []apiv1.EnvVar {
	env := getEnv(service, caps)
	var envVars []apiv1.EnvVar
	for _, s := range env {
		entry := strings.SplitN(s, "=", 2)
		envVars = append(envVars, apiv1.EnvVar{Name: entry[0], Value: entry[1]})

	}
	return envVars
}

func getResources(service ServiceBase) apiv1.ResourceRequirements {
	getRl := func() apiv1.ResourceList {
		rl := apiv1.ResourceList{}
		if service.Service.Cpu != "" {
			rl[apiv1.ResourceCPU] = resource.MustParse(service.Service.Cpu)
		}
		if service.Service.Mem != "" {
			rl[apiv1.ResourceMemory] = resource.MustParse(service.Service.Mem)
		}
		return rl
	}
	res := apiv1.ResourceRequirements{}
	res.Limits = getRl()
	res.Requests = getRl()
	return res
}

func getHostAliases(service *config.Browser) []apiv1.HostAlias {
	aliases := []apiv1.HostAlias{}
	fn := func(a apiv1.HostAlias) {
		aliases = append(aliases, a)
	}
	hosts := service.Hosts
	if len(hosts) > 0 {
		for _, host := range hosts {
			fn(spitHostAlias(host))
		}
	}
	return aliases
}

func getEmptyDirSizeLimit(service *config.Browser) *resource.Quantity {
	shm := resource.Quantity{}
	const unit = 1024
	if service.ShmSize < unit {
		shm = resource.MustParse(sizeLimitDefault)
	} else {
		div, exp := int64(unit), 0
		for n := service.ShmSize / unit; n >= unit; n /= unit {
			div *= unit
			exp++
		}
		shmSize := fmt.Sprintf("%.0f%ci", float64(service.ShmSize)/float64(div), "KMGTPE"[exp])
		shm = resource.MustParse(shmSize)
	}
	return &shm
}

func getContainerPort() []apiv1.ContainerPort {
	cp := []apiv1.ContainerPort{}
	fn := func(p apiv1.ContainerPort) {
		cp = append(cp, p)
	}
	fn(apiv1.ContainerPort{Name: "selenium", ContainerPort: selenium})
	fn(apiv1.ContainerPort{Name: "fileserver", ContainerPort: fileserver})
	fn(apiv1.ContainerPort{Name: "clipboard", ContainerPort: clipboard})
	fn(apiv1.ContainerPort{Name: "vnc", ContainerPort: vnc})
	fn(apiv1.ContainerPort{Name: "devtools", ContainerPort: devtools})
	return cp
}

func getSysCtl(m map[string]string) []apiv1.Sysctl {
	var s []apiv1.Sysctl
	for k, v := range m {
		s = append(s, apiv1.Sysctl{Name: k, Value: v})
	}
	return s
}

func spitHostAlias(alias string) apiv1.HostAlias {
	hostAlias := strings.Split(alias, ":")
	return apiv1.HostAlias{
		IP:        hostAlias[1],
		Hostnames: []string{hostAlias[0]},
	}
}

func StreamK8sPodLogs(requestId uint64, sess *session.Session, wsConn *websocket.Conn, sid string) error {
	log.Printf("[%d] [POD_LOGS] [%s]", requestId, sess.Pod.Name)
	k8sClient, err := getK8sClient()
	if err != nil {
		log.Printf("[%d] [KUBERNETES_CLIENT_ERROR] [%v]", requestId, err)
		return err
	}
	req := k8sClient.CoreV1().Pods(sess.Pod.Namespace).GetLogs(sess.Pod.Name, &apiv1.PodLogOptions{
		Container:  sess.Pod.ContainerName,
		Follow:     true,
		Previous:   false,
		Timestamps: false,
	})
	r, err := req.Stream(wsConn.Request().Context())
	if err != nil {
		log.Printf("[%d] [POD_LOGS_ERROR] [%s] [%v]", requestId, sess.Pod.Name, err)
		return err
	}
	defer r.Close()
	wsConn.PayloadType = websocket.BinaryFrame
	go func() {
		io.Copy(wsConn, r)
		wsConn.Close()
		log.Printf("[%d] [POD_LOGS_CLOSED] [%s] [%s]", requestId, sess.Pod.Name, sid)
	}()
	io.Copy(wsConn, r)
	log.Printf("[%d] [POD_LOGS_DISCONNECTED] [%s] [%s]", requestId, sess.Pod.Name, sid)
	return nil
}
