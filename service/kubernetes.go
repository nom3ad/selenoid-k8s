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

var k8sObjYamlSerializer = k8sJson.NewSerializerWithOptions(
	k8sJson.DefaultMetaFactory, nil, nil,
	k8sJson.SerializerOptions{
		Yaml:   true,
		Pretty: true,
		Strict: true,
	},
)

func getK8sClient() (*kubernetes.Clientset, error) {
	config, err := k8s_config.GetConfig()
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
	ns := k.Environment.OrchestratorOptions["k8sNamespace"]
	container := parseImageName(image)

	v1Pod := &apiv1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: container,
			Namespace:    ns,
			Labels:       getLabels(k.Service, k.Caps),
		},
		Spec: apiv1.PodSpec{
			Containers: []apiv1.Container{
				{
					Name:  container,
					Image: image,
					SecurityContext: &apiv1.SecurityContext{
						Privileged: &k.Privileged,
					},
					Env: getEnvVars(k.ServiceBase, k.Caps),

					Resources: getResources(k.ServiceBase),
					Ports:     getContainerPort(),
					VolumeMounts: []apiv1.VolumeMount{
						{
							Name:      "dshm",
							MountPath: "/dev/shm",
						},
					},
				},
			},
			Volumes: []apiv1.Volume{
				{
					Name: "dshm",
					VolumeSource: apiv1.VolumeSource{
						EmptyDir: &apiv1.EmptyDirVolumeSource{
							Medium:    apiv1.StorageMediumMemory,
							SizeLimit: getEmptyDirSizeLimit(k.Service),
						},
					},
				},
			},
			HostAliases:   getHostAliases(k.Service),
			RestartPolicy: apiv1.RestartPolicyNever,
		},
	}

	k8sPodSpecExtraOptions := k.Environment.OrchestratorOptions["k8sPodSpecExtraOptions"]
	if k8sPodSpecExtraOptions != "" {
		if json.Unmarshal([]byte(k8sPodSpecExtraOptions), &v1Pod.Spec) != nil {
			return nil, fmt.Errorf("failed to parse k8sPodSpecExtraOptions: %v | %w", k8sPodSpecExtraOptions, err)
		}
	}

	var buf bytes.Buffer
	_ = k8sObjYamlSerializer.Encode(v1Pod, &buf)
	// podYaml, _ := yaml.Marshal(v1Pod)
	log.Printf("[%d] [CREATING_POD] [%s] [%s] Pod=%s", requestID, image, ns, buf.String())

	podStartTime := time.Now()
	podObj, err := k8sClient.CoreV1().Pods(ns).Create(context.Background(), v1Pod, metav1.CreateOptions{})
	pod := podObj.GetName()
	if err != nil {
		deletePod(pod, ns, k8sClient, requestID)
		return nil, fmt.Errorf("start pod: %v", err)
	}

	if err := waitForPodToBeReady(k8sClient, podObj, ns, pod, k.StartupTimeout); err != nil {
		deletePod(pod, ns, k8sClient, requestID)
		return nil, fmt.Errorf("status pod: %v", err)
	}

	log.Printf("[%d] [POD_CREATED] [%s] [%s] [%.2fs]", requestID, pod, image, util.SecondsSince(podStartTime))

	podIP := getPodIP(pod, ns, k8sClient)
	hostPort := buildHostPort(podIP, k.Caps)

	u := &url.URL{Scheme: "http", Host: hostPort.Selenium}

	if err := wait(u.String(), k.StartupTimeout); err != nil {
		deletePod(pod, ns, k8sClient, requestID)
	}

	s := StartedService{
		Url: u,
		Pod: &session.Pod{
			ID:            string(podObj.GetUID()),
			IPAddress:     podIP,
			Name:          podObj.GetName(),
			ContainerName: container,
			Namespace:     ns,
		},
		HostPort: session.HostPort{
			Selenium:   hostPort.Selenium,
			Fileserver: hostPort.Fileserver,
			Clipboard:  hostPort.Clipboard,
			VNC:        hostPort.VNC,
			Devtools:   hostPort.Devtools,
		},
		Cancel: func() {
			defer deletePod(pod, ns, k8sClient, requestID)
		},
	}
	return &s, nil
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

func parseImageName(image string) (container string) {
	pref, err := regexp.Compile("[^a-zA-Z0-9]+")
	if err != nil {
		container = "selenoid_browser"
	}
	container = pref.ReplaceAllString(image, "-")
	return container
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

func waitForPodToBeReady(k8sClient *kubernetes.Clientset, pod *apiv1.Pod, ns, name string, timeout time.Duration) error {
	status := pod.Status
	w, err := k8sClient.CoreV1().Pods(ns).Watch(context.Background(), metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector("metadata.name", name).String(),
	})
	if err != nil {
		return err
	}
	func() {
		for {
			select {
			case events, ok := <-w.ResultChan():
				if !ok {
					return
				}
				resp := events.Object.(*apiv1.Pod)
				status = resp.Status
				if resp.Status.Phase != apiv1.PodPending {
					w.Stop()
				}
			case <-time.After(timeout):
				w.Stop()
			}
		}
	}()
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
	getLimits := func(req map[string]string) apiv1.ResourceList {
		res := apiv1.ResourceList{}
		if cpu, ok := req["cpu"]; ok {
			res[apiv1.ResourceCPU] = resource.MustParse(cpu)
		}
		if mem, ok := req["memory"]; ok {
			res[apiv1.ResourceMemory] = resource.MustParse(mem)
		}
		return res
	}
	res := apiv1.ResourceRequirements{}
	req := service.Service.Requirements
	if len(req.Limits) != 0 {
		res.Limits = getLimits(req.Limits)
	}
	if len(req.Requests) != 0 {
		res.Requests = getLimits(req.Requests)
	}
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
