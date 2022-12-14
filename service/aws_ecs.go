package service

import (
	"crypto/md5"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/aerokube/selenoid/session"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	aws_session "github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecs"
	"golang.org/x/net/websocket"
)

var flags = struct {
	awsECSRegion                   string
	awsECSClusterName              string
	awsECSExecutionRoleArn         string
	awsECSTaskRoleArn              string
	awsECSSubnetIDs                string
	awsECSecurityGroupIDs          string
	awsECSNetworkMode              string
	awsECSAssignPublicIP           bool
	awsECSCapacityProvider         string
	awsECSLogConfiguration         string
	awsECSTaskPlacementConstraints string
	awsECSTaskTags                 string
}{}

var ecs_session *aws_session.Session

func InitAWSElasticContainerServiceFlags() {
	flag.StringVar(&flags.awsECSRegion, "aws-ecs-region", "", "AWS ECS region")
	flag.StringVar(&flags.awsECSClusterName, "aws-ecs-cluster-name", "default", "AWS ECS Cluster name")
	flag.StringVar(&flags.awsECSExecutionRoleArn, "aws-ecs-execution-role-arn", "", "AWS ECS Execution role ARN")
	flag.StringVar(&flags.awsECSTaskRoleArn, "aws-ecs-task-role-arn", "", "AWS ECS Task role ARN")
	flag.StringVar(&flags.awsECSSubnetIDs, "aws-ecs-subnets", "", "Comma separated list of AWS VPC subnet IDs")
	flag.StringVar(&flags.awsECSecurityGroupIDs, "aws-ecs-security-group-id", "", "Comma separated list of AWS ECS Security group IDs")
	flag.StringVar(&flags.awsECSNetworkMode, "aws-ecs-network-mode", "awsvpc", "AWS ECS Network mode")
	flag.BoolVar(&flags.awsECSAssignPublicIP, "aws-ecs-assign-public-ip", false, "Whether to assign public IP to AWS ECS Task ENIs")
	flag.StringVar(&flags.awsECSCapacityProvider, "aws-ecs-capacity-provider", "FARGATE_SPOT", "AWS ECS capacity provider. FARGATE,FARGATE_SPOT or existing Auto Scaling group capacity provider")
	flag.StringVar(&flags.awsECSLogConfiguration, "aws-ecs-log-configuration", "", "AWS ECS ContainerDefinition.logConfiguration as JSON object string")
	flag.StringVar(&flags.awsECSTaskPlacementConstraints, "aws-ecs-task-placement-constraints", "", "AWS ECS []PlacementConstraint as JSON list string")
	flag.StringVar(&flags.awsECSTaskTags, "aws-ecs-task-tags", "", "AWS ECS Task tags as key1=value=1,key2=value2 format")
}

// AWSElasticContainerService
type AWSElasticContainerService struct {
	ServiceBase
	Environment
	session.Caps
}

func getECSClient() (*ecs.ECS, error) {
	var err error
	if ecs_session == nil {
		ecs_session, err = aws_session.NewSession(&aws.Config{
			Region: nonEmptyStringPtr(flags.awsECSRegion),
		})
		if err != nil {
			return nil, err
		}
	}
	return ecs.New(ecs_session), nil
}

// StartWithCancel - Starter interface implementation
func (s *AWSElasticContainerService) StartWithCancel() (*StartedService, error) {
	ecsClient, err := getECSClient()
	if err != nil {
		return nil, err
	}
	containerName := "selenoid"
	requestID := s.RequestId
	image := s.Service.Image.(string)

	taskDef, err := s.registerTaskDefinition(ecsClient, image, containerName, requestID)
	if err != nil {
		return nil, fmt.Errorf("could not register task definition: %w", err)
	}

	ecsTask, err := s.runTask(ecsClient, *taskDef.TaskDefinitionArn, containerName, requestID)
	if err != nil {
		return nil, fmt.Errorf("could not run task: %w", err)
	}
	containerIp, _ := s.getContainerInfo(*ecsTask)
	if containerIp == "" {
		return nil, fmt.Errorf("could not find a container ip")
	}
	taskArn := *ecsTask.TaskArn
	taskName := taskArn
	clusterArn := *ecsTask.ClusterArn
	hostPort := buildHostPort(containerIp, s.Caps)
	u := &url.URL{Scheme: "http", Host: hostPort.Selenium, Path: s.Service.Path}
	log.Printf("[%d] [SELENIUM_URL] [%s] [%s]", requestID, taskArn, u.String())

	if err := wait(u.String(), s.StartupTimeout); err != nil {
		s.stopTask(ecsClient, taskArn, clusterArn, requestID)
	}

	ss := StartedService{
		Orchestrator: "aws-ecs",
		Url:          u,
		Pod: &session.Pod{
			ID:            taskArn,
			IPAddress:     containerIp,
			Name:          taskName,
			ContainerName: containerName,
			Namespace:     clusterArn,
		},
		HostPort: hostPort,
		Cancel: func() {
			defer s.stopTask(ecsClient, taskArn, clusterArn, requestID)
		},
	}
	return &ss, nil
}

func (s *AWSElasticContainerService) registerTaskDefinition(ecsClient *ecs.ECS, image string, containerName string, requestID uint64) (*ecs.TaskDefinition, error) {
	image = fullyQualifiedImageName(image)
	requiresCompatibilities := []string{"EC2", "FARGATE"}
	dnServers := s.Caps.DNSServers
	networkMode := flags.awsECSNetworkMode
	if s.Environment.Network != "" {
		networkMode = s.Environment.Network
	}
	var logGroupConfiguration ecs.LogConfiguration
	if err := jsonUnmarshalOnTrimmedValue(flags.awsECSLogConfiguration, &logGroupConfiguration); err != nil {
		return nil, fmt.Errorf("invalid LogConfiguration: %q: %w", flags.awsECSLogConfiguration, err)
	}

	family := s.deriveTaskDefinitionFamilyName(image, containerName, requiresCompatibilities, dnServers, logGroupConfiguration)
	log.Printf("[%d] [CHECK_IF_TASK_DEFINITION_EXISTS] image=%s family=%s", requestID, image, family)
	describeOutput, err := ecsClient.DescribeTaskDefinition(&ecs.DescribeTaskDefinitionInput{
		TaskDefinition: &family,
	})
	if err == nil {
		log.Printf("[%d] [TASK_DEFINITION_FOUND] image=%s TaskDef=%s", requestID, image, *describeOutput.TaskDefinition.TaskDefinitionArn)
		return describeOutput.TaskDefinition, nil
	}
	if awsErr, ok := err.(awserr.Error); !ok || !strings.Contains(awsErr.Message(), "Unable to describe task definition") {
		return nil, err
	}
	containerDef := ecs.ContainerDefinition{
		Name:         &containerName,
		Image:        &image,
		Memory:       aws.Int64(128), // Dummy, will override in task run
		PortMappings: s.getPortMapping(),
		DnsServers:   aws.StringSlice(dnServers),
	}
	if aws.StringValue(logGroupConfiguration.LogDriver) != "" {
		containerDef.LogConfiguration = &logGroupConfiguration
	}
	taskDefRegisterInput := ecs.RegisterTaskDefinitionInput{
		RequiresCompatibilities: aws.StringSlice(requiresCompatibilities),
		Family:                  &family,
		ContainerDefinitions:    []*ecs.ContainerDefinition{&containerDef},
		NetworkMode:             aws.String(networkMode), // For FARGATE, awsvpc is only supported
		Cpu:                     aws.String("256"),       // FARGATE Dummy, will override in task run
		Memory:                  aws.String("512"),       // FARGATE Dummy, will override in task run
	}
	log.Printf("[%d] [REGISTERING_TASK_DEFINITION] family=%s TaskDef=%s", requestID, family, jsonMarshal(taskDefRegisterInput))
	taskDefRegisterOutput, err := ecsClient.RegisterTaskDefinition(&taskDefRegisterInput)
	if err != nil {
		return nil, err
	}
	return taskDefRegisterOutput.TaskDefinition, nil
}

func (s *AWSElasticContainerService) deriveTaskDefinitionFamilyName(image string, values ...any) string {
	// FamilyName: Up to 255 letters (uppercase and lowercase), digits, hyphens, and underscores are allowed.
	// Container image name: may contain lowercase and uppercase letters, digits, underscores, hyphens and periods, and "/" as label seperator
	hashInput := image
	for _, v := range values {
		if v != nil {
			hashInput += jsonMarshal(v)
		}
	}
	hash := md5.Sum([]byte(hashInput))
	replacer := strings.NewReplacer(".", "_", "/", "_")
	familyName := replacer.Replace(image) + "-" + base64.RawURLEncoding.EncodeToString(hash[:8])
	return familyName
}

func (s *AWSElasticContainerService) runTask(ecsClient *ecs.ECS, taskDefArn string, containerName string, requestID uint64) (*ecs.Task, error) {
	clusterName := flags.awsECSClusterName
	executionRoleArn := flags.awsECSExecutionRoleArn
	taskRoleArn := flags.awsECSTaskRoleArn
	var capacityProviderStrategy []*ecs.CapacityProviderStrategyItem
	if flags.awsECSCapacityProvider != "" {
		capacityProviderStrategy = []*ecs.CapacityProviderStrategyItem{
			{
				Weight:           aws.Int64(100),
				CapacityProvider: &flags.awsECSCapacityProvider,
			},
		}
	}
	var placementConstrains []*ecs.PlacementConstraint
	if err := jsonUnmarshalOnTrimmedValue(flags.awsECSTaskPlacementConstraints, &placementConstrains); err != nil {
		return nil, fmt.Errorf("invalid TaskPlacementConstraints: %q: %w", flags.awsECSTaskPlacementConstraints, err)
	}
	var networkConfiguration *ecs.NetworkConfiguration
	if flags.awsECSNetworkMode == "awsvpc" {
		assignPublicIP := "DISABLED"
		if flags.awsECSAssignPublicIP {
			assignPublicIP = "ENABLED"
		}
		securityGroups := parseCommaSeparatedString(flags.awsECSecurityGroupIDs)
		subnets := parseCommaSeparatedString(flags.awsECSSubnetIDs)
		if len(subnets) == 0 {
			return nil, fmt.Errorf("no subnets found")
		}
		networkConfiguration = &ecs.NetworkConfiguration{
			AwsvpcConfiguration: &ecs.AwsVpcConfiguration{
				Subnets:        aws.StringSlice(subnets), // required
				AssignPublicIp: &assignPublicIP,
				SecurityGroups: aws.StringSlice(securityGroups),
			},
		}
	}
	tags := s.getTags()

	var cpu, memory string
	if s.Service.Cpu != "" {
		cpu = s.Service.Cpu
	} else if s.Environment.CPU > 0 {
		cpu = fmt.Sprint(s.Environment.CPU)
	}
	if s.Service.Mem != "" {
		memory = s.Service.Mem
	} else if s.Environment.Memory > 0 {
		memory = fmt.Sprint(s.Environment.Memory)
	}

	var command []*string
	environment := s.getEnvVars(s.ServiceBase, s.Caps)
	startedBy := "selenoid"
	enableExecuteCommand := false
	enableECSManagedTags := true

	taskRunInput := ecs.RunTaskInput{
		TaskDefinition:           &taskDefArn,
		Count:                    aws.Int64(1),
		Cluster:                  nonEmptyStringPtr(clusterName),
		StartedBy:                &startedBy,
		Tags:                     tags,
		CapacityProviderStrategy: capacityProviderStrategy,
		NetworkConfiguration:     networkConfiguration,
		EnableECSManagedTags:     &enableECSManagedTags,
		EnableExecuteCommand:     &enableExecuteCommand,
		PlacementConstraints:     placementConstrains,
		Overrides: &ecs.TaskOverride{
			Cpu:              nonEmptyStringPtr(cpu),
			Memory:           nonEmptyStringPtr(memory),
			ExecutionRoleArn: nonEmptyStringPtr(executionRoleArn),
			TaskRoleArn:      nonEmptyStringPtr(taskRoleArn),
			ContainerOverrides: []*ecs.ContainerOverride{
				{
					Name:        &containerName,
					Command:     command,
					Environment: environment,
					// EnvironmentFiles: ,
					// Cpu: ,
					// Memory: ,
					// MemoryReservation:
					// ResourceRequirements: , ,
				},
			},
			// EphemeralStorage: ,
			// InferenceAcceleratorOverrides: ,
		},
		// PlatformVersion: Will use LATEST for Fargate,
		// Group: The default value is the family name of the task definition,
		// LaunchType: contradict CapacityProviderStrategy,
		// PlacementStrategy: ,
		// PropagateTags: ,
		// ReferenceId: ,
	}

	log.Printf("[%d] [STARTING_TASK] [%s] [%s] Task=%s", requestID, taskDefArn, clusterName, jsonMarshal(taskRunInput))

	runTaskOutput, err := ecsClient.RunTask(&taskRunInput)
	if err != nil {
		return nil, err
	}
	task := runTaskOutput.Tasks[0]
	checkInterval := 6 * time.Second
	maxAttempts := 100
	attempt := 0
	for {
		attempt += 1
		if attempt > maxAttempts {
			return nil, fmt.Errorf("timeout while waiting for task - %s", *task.TaskArn)
		}
		ip, agentStatus := s.getContainerInfo(*task)
		log.Printf("[%d] [WAITING_FOR_TASK] [%s] [lastStatus:%s] [connectivity: %s] [IP: %s] [Agents: %s]",
			requestID, *task.TaskArn, aws.StringValue(task.LastStatus), aws.StringValue(task.Connectivity), ip, agentStatus)
		describeTaskOutput, err := ecsClient.DescribeTasks(&ecs.DescribeTasksInput{
			Cluster: &clusterName,
			Tasks:   []*string{task.TaskArn},
		})
		if err != nil {
			return nil, err
		}
		if len(describeTaskOutput.Failures) > 0 {
			return nil, fmt.Errorf("unexpected failure: arn=%s reason=%s details=%s", aws.StringValue(runTaskOutput.Failures[0].Arn), aws.StringValue(runTaskOutput.Failures[0].Reason), aws.StringValue(runTaskOutput.Failures[0].Reason))
		}
		task = describeTaskOutput.Tasks[0]
		if aws.StringValue(task.LastStatus) == "RUNNING" {
			log.Printf("[%d] [TASK_RUNNING] [%s]", requestID, *task.TaskArn)
			return task, nil
		}
		if aws.StringValue(task.LastStatus) == "STOPPED" {
			return nil, fmt.Errorf("task was stopped unexpectedly. %s (code=%s)", aws.StringValue(task.StoppedReason), aws.StringValue(task.StopCode))
		}
		time.Sleep(checkInterval)
	}
}

func (s *AWSElasticContainerService) getContainerInfo(task ecs.Task) (ipAddress string, agentStatus string) {
	if len(task.Containers) == 0 {
		return
	}
	mainContainer := task.Containers[0]
	// mainContainer.ManagedAgents
	for _, ni := range mainContainer.NetworkInterfaces {
		if aws.StringValue(ni.PrivateIpv4Address) != "" {
			ipAddress = aws.StringValue(ni.PrivateIpv4Address)
		}
	}
	for _, ma := range mainContainer.ManagedAgents {
		agentStatus += fmt.Sprintf("<%s:%s (%s)>", aws.StringValue(ma.Name), aws.StringValue(ma.LastStatus), aws.StringValue(ma.Reason))
	}
	return
}

func (s *AWSElasticContainerService) getTags() []*ecs.Tag {
	var tags []*ecs.Tag
	for k, v := range parseKVString(flags.awsECSTaskTags) {
		tags = append(tags, &ecs.Tag{Key: aws.String(k), Value: aws.String(v)})
	}
	labels := getLabels(s.Service, s.Caps)
	for k, v := range labels {
		tags = append(tags, &ecs.Tag{Key: aws.String(k), Value: aws.String(v)})
	}
	return tags
}

func (s *AWSElasticContainerService) getPortMapping() []*ecs.PortMapping {
	var ports []*ecs.PortMapping
	ports = append(ports, &ecs.PortMapping{ContainerPort: int64Ptr(Ports.Selenium), HostPort: int64Ptr(Ports.Selenium)})
	ports = append(ports, &ecs.PortMapping{ContainerPort: int64Ptr(Ports.Fileserver), HostPort: int64Ptr(Ports.Fileserver)})
	ports = append(ports, &ecs.PortMapping{ContainerPort: int64Ptr(Ports.Clipboard), HostPort: int64Ptr(Ports.Clipboard)})
	ports = append(ports, &ecs.PortMapping{ContainerPort: int64Ptr(Ports.VNC), HostPort: int64Ptr(Ports.VNC)})
	ports = append(ports, &ecs.PortMapping{ContainerPort: int64Ptr(Ports.Devtools), HostPort: int64Ptr(Ports.Devtools)})
	return ports
}

func (s *AWSElasticContainerService) getEnvVars(service ServiceBase, caps session.Caps) []*ecs.KeyValuePair {
	env := getEnv(service, caps)
	var envVars []*ecs.KeyValuePair
	for _, s := range env {
		entry := strings.SplitN(s, "=", 2)
		envVars = append(envVars, &ecs.KeyValuePair{Name: aws.String(entry[0]), Value: aws.String(entry[1])})

	}
	return envVars
}

func (s *AWSElasticContainerService) stopTask(ecsClient *ecs.ECS, task string, cluster string, requestID uint64) {
	reason := "stopTask()"
	input := &ecs.StopTaskInput{
		Cluster: &cluster,
		Reason:  &reason,
		Task:    &task,
	}
	log.Printf("[%d] [STOPPING_TASK] [%s] [%s]", requestID, cluster, task)
	_, err := ecsClient.StopTask(input)
	if err != nil {
		log.Printf("[%d] [TASK_STOP_ERROR] [%s] [%s] [%s]", requestID, cluster, task, err)
		return
	}
	log.Printf("[%d] [TASK_STOPPED] [%s] [%s]", requestID, cluster, task)
}

func StreamAWSECSContainerLogs(requestId uint64, sess *session.Session, wsConn *websocket.Conn, sid string) (err error) {
	log.Printf("[%d] [ECS_CONTAINER_LOGS] [%s/%s]", requestId, sess.Pod.Name, sess.Pod.ContainerName)
	return fmt.Errorf("not implemented")
}
