package service

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/aerokube/selenoid/session"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	aws_session "github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go/service/ecs"
)

var flags = struct {
	AwsECSRegion                   string
	AwsECSClusterName              string
	AwsECSExecutionRoleArn         string
	AwsECSTaskRoleArn              string
	AwsECSSubnetIDs                string
	AwsECSecurityGroupIDs          string
	AwsECSNetworkMode              string
	AwsECSAssignPublicIP           bool
	AwsECSCapacityProvider         string
	AwsECSLogConfiguration         string
	AwsECSTaskPlacementConstraints string
	AwsECSTaskTags                 string
	AwsECSTaskDefinitionNamePrefix string
}{}

var awsSession *aws_session.Session

func InitAWSElasticContainerServiceFlags() {
	flag.StringVar(&flags.AwsECSRegion, "aws-ecs-region", "", "AWS ECS region")
	flag.StringVar(&flags.AwsECSClusterName, "aws-ecs-cluster-name", "default", "AWS ECS Cluster name")
	flag.StringVar(&flags.AwsECSExecutionRoleArn, "aws-ecs-execution-role-arn", "", "AWS ECS Execution role ARN")
	flag.StringVar(&flags.AwsECSTaskRoleArn, "aws-ecs-task-role-arn", "", "AWS ECS Task role ARN")
	flag.StringVar(&flags.AwsECSSubnetIDs, "aws-ecs-subnets", "", "Comma separated list of AWS VPC subnet IDs")
	flag.StringVar(&flags.AwsECSecurityGroupIDs, "aws-ecs-security-group-id", "", "Comma separated list of AWS ECS Security group IDs")
	flag.StringVar(&flags.AwsECSNetworkMode, "aws-ecs-network-mode", "awsvpc", "AWS ECS Network mode")
	flag.BoolVar(&flags.AwsECSAssignPublicIP, "aws-ecs-assign-public-ip", false, "Whether to assign public IP to AWS ECS Task ENIs")
	flag.StringVar(&flags.AwsECSCapacityProvider, "aws-ecs-capacity-provider", "FARGATE_SPOT", "AWS ECS capacity provider. FARGATE,FARGATE_SPOT or existing Auto Scaling group capacity provider")
	flag.StringVar(&flags.AwsECSLogConfiguration, "aws-ecs-log-configuration", "", "AWS ECS ContainerDefinition.logConfiguration as JSON object string. eg:  {\"logDriver\":\"awslogs\",\"options\":{\"awslogs-group\":\"ecs/selenoid\"}}")
	flag.StringVar(&flags.AwsECSTaskPlacementConstraints, "aws-ecs-task-placement-constraints", "", "AWS ECS []PlacementConstraint as JSON list string")
	flag.StringVar(&flags.AwsECSTaskTags, "aws-ecs-task-tags", "", "AWS ECS Task tags as key1=value=1,key2=value2 format")
	flag.StringVar(&flags.AwsECSTaskDefinitionNamePrefix, "aws-ecs-task-definition-name-prefix", "", "AWS ECS Task definition name prefix")
}

// AWSElasticContainerService
type AWSElasticContainerService struct {
	ServiceBase
	Environment
	session.Caps
}

func getECSClient() (*ecs.ECS, error) {
	var err error
	if awsSession == nil {
		log.Printf("Flags: %s", jsonMarshal(flags))
		awsSession, err = aws_session.NewSession(&aws.Config{
			Region: nonEmptyStringPtr(flags.AwsECSRegion),
		})
		if err != nil {
			return nil, err
		}
	}
	return ecs.New(awsSession), nil
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

	taskDefinition, err := s.registerTaskDefinition(ecsClient, image, containerName, requestID)
	if err != nil {
		return nil, fmt.Errorf("could not register task definition: %w", err)
	}

	ecsTask, err := s.runTask(ecsClient, *taskDefinition.TaskDefinitionArn, containerName, requestID)
	if err != nil {
		return nil, fmt.Errorf("could not run task: %w", err)
	}
	containerRuntimeId, containerIp, _ := s.getContainerInfo(*ecsTask)
	if containerIp == "" {
		return nil, fmt.Errorf("could not find a container ip")
	}
	taskArn := *ecsTask.TaskArn
	taskId := strings.Split(taskArn, "/")[2] //arn:aws:ecs:us-east-1:1234567890:task/<cluster>/xxxxxxxxx
	clusterArn := *ecsTask.ClusterArn
	logConfiguration := taskDefinition.ContainerDefinitions[0].LogConfiguration
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
			Name:          taskId,
			ContainerName: containerName,
			ContainerId:   containerRuntimeId,
			Namespace:     clusterArn,
			IPAddress:     containerIp,
			Configuration: map[string]string{
				"logConfiguration": jsonMarshal(logConfiguration),
			},
		},
		HostPort: hostPort,
		Cancel: func() {
			defer s.stopTask(ecsClient, taskArn, clusterArn, requestID)
		},
	}
	return &ss, nil
}

func (s *AWSElasticContainerService) registerTaskDefinition(ecsClient *ecs.ECS, image string, containerName string, requestID uint64) (*ecs.TaskDefinition, error) {
	requiresCompatibilities := []string{ecs.CompatibilityEc2, ecs.CompatibilityFargate}
	dnServers := s.Caps.DNSServers
	networkMode := flags.AwsECSNetworkMode
	if s.Environment.Network != "default" && s.Environment.Network != "" {
		networkMode = s.Environment.Network
	}
	var logConfiguration ecs.LogConfiguration
	if err := jsonUnmarshalIfNonEmpty(flags.AwsECSLogConfiguration, &logConfiguration); err != nil {
		return nil, fmt.Errorf("invalid LogConfiguration: %q: %w", flags.AwsECSLogConfiguration, err)
	}
	if aws.StringValue(logConfiguration.LogDriver) == "awslogs" {
		// https://docs.aws.amazon.com/AmazonECS/latest/developerguide/using_awslogs.html#specify-log-config
		if aws.StringValue(logConfiguration.Options["awslogs-region"]) == "" {
			// If not specified, use task's region
			logConfiguration.Options["awslogs-region"] = ecsClient.Config.Region
		}
		if aws.StringValue(logConfiguration.Options["awslogs-group"]) == "" {
			// Optional for the EC2 launch type, required for the Fargate launch type.
			logConfiguration.Options["awslogs-group"] = aws.String("ecs/selenoid")
		}
		if aws.StringValue(logConfiguration.Options["awslogs-stream-prefix"]) == "" {
			// Optional for the EC2 launch type, required for the Fargate launch type.
			logConfiguration.Options["awslogs-stream-prefix"] = aws.String(s.BrowserName())
		}
	}

	family := s.deriveTaskDefinitionFamilyName(image, containerName, requiresCompatibilities, dnServers, logConfiguration)
	image = fullyQualifiedImageName(image)
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
		Memory:       aws.Int64(512), // Dummy, will override in task run
		PortMappings: s.getPortMapping(),
		DnsServers:   aws.StringSlice(dnServers),
	}
	taskDefRegisterInput := ecs.RegisterTaskDefinitionInput{
		RequiresCompatibilities: aws.StringSlice(requiresCompatibilities),
		Family:                  &family,
		ContainerDefinitions:    []*ecs.ContainerDefinition{&containerDef},
		NetworkMode:             aws.String(networkMode), // For FARGATE, awsvpc is only supported
		Cpu:                     aws.String("256"),       // FARGATE Dummy, will override in task run
		Memory:                  aws.String("512"),       // FARGATE Dummy, will override in task run
	}
	if aws.StringValue(logConfiguration.LogDriver) != "" {
		containerDef.LogConfiguration = &logConfiguration
		taskDefRegisterInput.ExecutionRoleArn = aws.String(flags.AwsECSExecutionRoleArn)
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
	replacer := strings.NewReplacer(".", "_", "/", "_", ":", "_")
	familyName := flags.AwsECSTaskDefinitionNamePrefix + replacer.Replace(image) + "-" + base64.RawURLEncoding.EncodeToString(hash[:8])
	return familyName
}

func (s *AWSElasticContainerService) runTask(ecsClient *ecs.ECS, taskDefArn string, containerName string, requestID uint64) (*ecs.Task, error) {
	clusterName := flags.AwsECSClusterName
	executionRoleArn := flags.AwsECSExecutionRoleArn
	taskRoleArn := flags.AwsECSTaskRoleArn
	var capacityProviderStrategy []*ecs.CapacityProviderStrategyItem
	if flags.AwsECSCapacityProvider != "" {
		capacityProviderStrategy = []*ecs.CapacityProviderStrategyItem{
			{
				Weight:           aws.Int64(100),
				CapacityProvider: &flags.AwsECSCapacityProvider,
			},
		}
	}
	var placementConstrains []*ecs.PlacementConstraint
	if err := jsonUnmarshalIfNonEmpty(flags.AwsECSTaskPlacementConstraints, &placementConstrains); err != nil {
		return nil, fmt.Errorf("invalid TaskPlacementConstraints: %q: %w", flags.AwsECSTaskPlacementConstraints, err)
	}
	var networkConfiguration *ecs.NetworkConfiguration
	if flags.AwsECSNetworkMode == "awsvpc" {
		assignPublicIP := "DISABLED"
		if flags.AwsECSAssignPublicIP {
			assignPublicIP = "ENABLED"
		}
		securityGroups := parseCommaSeparatedString(flags.AwsECSecurityGroupIDs)
		subnets := parseCommaSeparatedString(flags.AwsECSSubnetIDs)
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
	var err error
	var cpu int = 256    // Fargate minimum value
	var memory int = 512 // Fargate minimum value
	ecsTaskSizeDocLink := "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html#task_size"
	validTaskSizes := map[int][]int{
		256:   {512, 1 * 1024, 2 * 1024},
		512:   Range(1*1024, 4*1024, 1*1024),
		1024:  Range(2*1024, 8*1024, 1*1024),
		2048:  Range(4*1024, 16*1024, 1*1024),
		4096:  Range(8*1024, 30*1024, 1*1024),
		8192:  Range(16*1024, 60*1024, 4*1024),
		16384: Range(32*1024, 120*1024, 8*1024),
	}

	if s.Caps.Cpu != "" {
		if cpu, err = strconv.Atoi(s.Caps.Cpu); err != nil {
			return nil, fmt.Errorf("invalid cpu value found in capabilities: %s | valid values: %v | see %s", s.Service.Cpu, Keys(validTaskSizes), ecsTaskSizeDocLink)
		}
	} else if s.Service.Cpu != "" {
		if cpu, err = strconv.Atoi(s.Service.Cpu); err != nil {
			return nil, fmt.Errorf("invalid cpu value found in browser config: %s | valid values: %v | see %s", s.Service.Cpu, Keys(validTaskSizes), ecsTaskSizeDocLink)
		}
	} else if s.Environment.CPU > 0 {
		cpu = int(s.Environment.CPU)
	}
	if _, ok := validTaskSizes[cpu]; !ok {
		return nil, fmt.Errorf("invalid cpu value: %s, valid values are: %v | See %s", s.Service.Mem, Keys(validTaskSizes), ecsTaskSizeDocLink)
	}
	validMemValues := validTaskSizes[cpu]
	if s.Caps.Mem != "" {
		if memory, err = strconv.Atoi(s.Caps.Mem); err != nil {
			return nil, fmt.Errorf("invalid mem value found in capabilities: %s | valid values: %v | see %s", s.Service.Cpu, validMemValues, ecsTaskSizeDocLink)
		}
	} else if s.Service.Mem != "" {
		if memory, err = strconv.Atoi(s.Service.Mem); err != nil {
			return nil, fmt.Errorf("invalid mem value found in browser config: %s | valid values: %v | see %s", s.Service.Cpu, validMemValues, ecsTaskSizeDocLink)
		}
	} else if s.Environment.Memory > 0 {
		memory = int(s.Environment.Memory)
	} else {
		memory = validMemValues[0] // valid min memory value for given cpu value
	}
	if !Contains(validMemValues, memory) {
		return nil, fmt.Errorf("invalid mem value: %sMiB, For cpu=%d, valid values are %v | See %s", s.Service.Mem, cpu, validMemValues, ecsTaskSizeDocLink)
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
		PropagateTags:            aws.String("TASK_DEFINITION"),
		CapacityProviderStrategy: capacityProviderStrategy,
		NetworkConfiguration:     networkConfiguration,
		EnableECSManagedTags:     &enableECSManagedTags,
		EnableExecuteCommand:     &enableExecuteCommand,
		PlacementConstraints:     placementConstrains,
		Overrides: &ecs.TaskOverride{
			Cpu:              aws.String(strconv.Itoa(cpu)),
			Memory:           aws.String(strconv.Itoa(memory)),
			ExecutionRoleArn: nonEmptyStringPtr(executionRoleArn),
			TaskRoleArn:      nonEmptyStringPtr(taskRoleArn),
			ContainerOverrides: []*ecs.ContainerOverride{
				{
					Name:        &containerName,
					Command:     command,
					Environment: environment,
					Cpu:         int64Ptr(cpu),
					Memory:      int64Ptr(memory),
					// EnvironmentFiles: ,
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
		containerRuntimeId, ip, agentStatus := s.getContainerInfo(*task)
		// https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-lifecycle.html
		if aws.StringValue(task.LastStatus) == "RUNNING" {
			log.Printf("[%d] [TASK_RUNNING] [%s] [containerId: %s] %s", requestID, *task.TaskArn, containerRuntimeId, jsonMarshal(task))
			return task, nil
		}
		if aws.StringValue(task.LastStatus) == "STOPPED" {
			return nil, fmt.Errorf("task was stopped unexpectedly. %s (code=%s)", aws.StringValue(task.StoppedReason), aws.StringValue(task.StopCode))
		}
		log.Printf("[%d] [WAITING_FOR_TASK] [%s] [lastStatus:%s] [Container:%s] [connectivity: %s] [IP: %s] [Agents: %s]",
			requestID, *task.TaskArn, aws.StringValue(task.LastStatus), containerRuntimeId, aws.StringValue(task.Connectivity), ip, agentStatus)
		time.Sleep(checkInterval)
	}
}

func (s *AWSElasticContainerService) getContainerInfo(task ecs.Task) (containerRuntimeId, ipAddress, agentStatus string) {
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
	containerRuntimeId = aws.StringValue(mainContainer.RuntimeId)
	for _, ma := range mainContainer.ManagedAgents {
		agentStatus += fmt.Sprintf("<%s:%s (%s)>", aws.StringValue(ma.Name), aws.StringValue(ma.LastStatus), aws.StringValue(ma.Reason))
	}
	return
}

func (s *AWSElasticContainerService) getTags() []*ecs.Tag {
	var tags []*ecs.Tag
	for k, v := range parseKVString(flags.AwsECSTaskTags) {
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

func StreamAWSECSContainerLogs(ctx context.Context, requestId uint64, sess *session.Session, writer io.Writer, sid string) (err error) {
	log.Printf("[%d] [ECS_CONTAINER_LOGS] [%s/%s]", requestId, sess.Pod.Name, sess.Pod.ContainerId)

	var logConfiguration ecs.LogConfiguration
	if err := jsonUnmarshalIfNonEmpty(sess.Pod.Configuration["logConfiguration"], &logConfiguration); err != nil {
		return fmt.Errorf("invalid LogConfiguration: %q: %w", sess.Pod.Configuration["logConfiguration"], err)
	}
	if aws.StringValue(logConfiguration.LogDriver) != "awslogs" {
		return fmt.Errorf("unsupported log-driver: %q", aws.StringValue(logConfiguration.LogDriver))
	}
	region := aws.StringValue(logConfiguration.Options["awslogs-region"])
	logGroupName := aws.StringValue(logConfiguration.Options["awslogs-group"])
	logStreamPrefix := aws.StringValue(logConfiguration.Options["awslogs-stream-prefix"])
	taskArn := sess.Pod.ID
	taskId := strings.Split(taskArn, "/")[2]
	// https://docs.aws.amazon.com/AmazonECS/latest/developerguide/using_awslogs.html
	logStreamName := logStreamPrefix + "/" + sess.Pod.ContainerName + "/" + taskId

	cwLogsClient := cloudwatchlogs.New(awsSession, &aws.Config{Region: &region})

	getLogEventsInput := cloudwatchlogs.GetLogEventsInput{
		StartFromHead: aws.Bool(true),
		LogGroupName:  &logGroupName,
		LogStreamName: &logStreamName,
	}
	for {
		log.Printf("[%d] [GET_LOG_EVENTS] [%s|%s] ", requestId, logGroupName, logStreamName)
		output, err := cwLogsClient.GetLogEventsWithContext(ctx, &getLogEventsInput)
		if err != nil {
			return fmt.Errorf("error while GetLogEvents(): %w", err)
		}
		if len(output.Events) == 0 {
			_, err := io.WriteString(writer, "")
			if err != nil {
				return fmt.Errorf("ws ping write error: %w", err)
			}
		} else {
			for _, ev := range output.Events {
				msg := aws.StringValue(ev.Message)
				ts := time.UnixMilli(aws.Int64Value(ev.Timestamp)).Format("2006-01-02T15:04:05")
				line := ts + " " + msg + "\n"
				_, err := io.WriteString(writer, line)
				if err != nil {
					return fmt.Errorf("ws log write error: %w", err)
				}
			}
		}
		getLogEventsInput.NextToken = output.NextForwardToken
		time.Sleep(1 * time.Second)
	}
}
