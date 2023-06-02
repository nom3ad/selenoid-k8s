package service

import (
	"context"
	"flag"
	"log"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/aerokube/selenoid/session"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/containerinstances"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/pkg/errors"
)

var ociFlags = struct {
	OCIAvailabilityDomain string
	OCCompartmentID       string
	OCISubnetID           string
	OCISecurityGroupIds   string
	OCIConfigProfile      string
	OCIConfigFile         string
}{}

func InitOCIContainerInstancesServiceFlags() {
	flag.StringVar(&ociFlags.OCIAvailabilityDomain, "oci-availability-domain", "", "OCI Availability Domain")
	flag.StringVar(&ociFlags.OCCompartmentID, "oci-compartment-id", "", "OCI Compartment ID")
	flag.StringVar(&ociFlags.OCISubnetID, "oci-subnet-id", "", "OCI Subnet ID")
	flag.StringVar(&ociFlags.OCISecurityGroupIds, "oci-security-group-ids", "", "OCI Security Group IDs")
	flag.StringVar(&ociFlags.OCIConfigProfile, "oci-config-profile", "DEFAULT", "OCI Config Profile")
	flag.StringVar(&ociFlags.OCIConfigFile, "oci-config-file", "", "OCI Config File")
}

type OCIContainerInstancesService struct {
	ServiceBase
	Environment
	session.Caps
}

func getOCIConfigurationProvider() common.ConfigurationProvider {
	providers := []common.ConfigurationProvider{common.DefaultConfigProvider()}
	configFilePath := ociFlags.OCIConfigFile
	if configFilePath == "" {
		homeDir := os.Getenv("HOME")
		current, e := user.Current()
		if e == nil {
			homeDir = current.HomeDir
		}
		configFilePath = filepath.Join(homeDir, ".oci", "config")
	}
	if ociFlags.OCIConfigProfile != "" {
		cp, _ := common.ConfigurationProviderFromFileWithProfile(configFilePath, ociFlags.OCIConfigProfile, "")
		providers = append(providers, cp)
	}
	provider, _ := common.ComposingConfigurationProvider(providers)
	return provider
}

// StartWithCancel - Starter interface implementation
func (s *OCIContainerInstancesService) StartWithCancel() (*StartedService, error) {
	log.Printf("[%d] StartWithCancel() %s", s.RequestId, jsonMarshal(ociFlags))
	ctx := context.Background()
	ociClient, err := containerinstances.NewContainerInstanceClientWithConfigurationProvider(getOCIConfigurationProvider())
	if err != nil {
		return nil, err
	}
	containerDisplayName := "selenoid"
	requestID := s.RequestId
	image := s.Service.Image.(string)
	containerInstanceDisplayName := sanitizeStringAsValidDNSLabel(image)
	instanceShape := "CI.Standard.E4.Flex"
	isPublicIpAssigned := true
	// create instance
	createReq := containerinstances.CreateContainerInstanceRequest{
		CreateContainerInstanceDetails: containerinstances.CreateContainerInstanceDetails{
			CompartmentId:      &ociFlags.OCCompartmentID,
			AvailabilityDomain: nonEmptyStringPtrOrNil(ociFlags.OCIAvailabilityDomain),
			// FaultDomain: common.String("EXAMPLE-faultDomain-Value"),
			DisplayName: &containerInstanceDisplayName,
			Shape:       &instanceShape,
			ShapeConfig: &containerinstances.CreateContainerInstanceShapeConfigDetails{
				Ocpus:       common.Float32(1),
				MemoryInGBs: common.Float32(1),
			},
			ContainerRestartPolicy: containerinstances.ContainerInstanceContainerRestartPolicyNever,
			Containers: []containerinstances.CreateContainerDetails{{
				DisplayName:                 &containerDisplayName,
				ImageUrl:                    common.String(fullyQualifiedImageName(image)),
				Command:                     nil,
				Arguments:                   nil,
				EnvironmentVariables:        s.getEnvVars(s.ServiceBase, s.Caps),
				IsResourcePrincipalDisabled: common.Bool(false),
			}},
			Vnics: []containerinstances.CreateContainerVnicDetails{{
				DisplayName:         common.String("for-" + containerInstanceDisplayName),
				IsPublicIpAssigned:  &isPublicIpAssigned,
				NsgIds:              parseCommaSeparatedString(ociFlags.OCISecurityGroupIds),
				SubnetId:            nonEmptyStringPtrOrNil(ociFlags.OCISubnetID),
				SkipSourceDestCheck: common.Bool(true),
			}},
			GracefulShutdownTimeoutInSeconds: common.Int64(15),
		},
	}

	log.Printf("[%d] CreateContainerInstance() <- %s", requestID, createReq)
	createResp, err := ociClient.CreateContainerInstance(ctx, createReq)
	if err != nil {
		return nil, err
	}
	containerInstanceId := *createResp.ContainerInstance.Id
	log.Printf("[%d] CreateContainerInstance() -> %s", requestID, createResp)
	err = func() error {
		for {
			<-time.After(2 * time.Second)
			log.Printf("[%d] [WaitForWorkRequest]", requestID)
			wrResp, err := ociClient.GetWorkRequest(ctx, containerinstances.GetWorkRequestRequest{
				WorkRequestId: createResp.OpcWorkRequestId,
			})
			if err != nil {
				return errors.Errorf("WorkRequest get failed: %w", err)
			}
			switch wrResp.Status {
			case containerinstances.OperationStatusSucceeded:
				log.Printf("[%d] [WaitForWorkRequest] [Status: %s]", requestID, wrResp.WorkRequest.Status)
				return nil
			case containerinstances.OperationStatusFailed:
				return errors.Errorf("WorkRequest failed: %s", wrResp.WorkRequest)
			}
		}
	}()
	if err != nil {
		s.deleteContainerInstance(ociClient, containerInstanceId, requestID)
		return nil, err
	}

	getContainerResp, err := ociClient.GetContainerInstance(ctx, containerinstances.GetContainerInstanceRequest{
		ContainerInstanceId: &containerInstanceId,
	})

	if err != nil {
		s.deleteContainerInstance(ociClient, containerInstanceId, requestID)
		return nil, err
	}
	log.Printf("[%d] GetContainerInstance() -> %s", requestID, getContainerResp)

	vnicId := getContainerResp.ContainerInstance.Vnics[0].VnicId
	vncClient, err := core.NewVirtualNetworkClientWithConfigurationProvider(getOCIConfigurationProvider())
	if err != nil {
		s.deleteContainerInstance(ociClient, containerInstanceId, requestID)
		return nil, err
	}
	vnicResp, err := vncClient.GetVnic(ctx, core.GetVnicRequest{VnicId: vnicId})
	if err != nil {
		s.deleteContainerInstance(ociClient, containerInstanceId, requestID)
		return nil, err
	}

	var containerIp string
	if isPublicIpAssigned {
		containerIp = *vnicResp.PublicIp
	} else {
		containerIp = *vnicResp.PrivateIp
	}

	hostPort := buildHostPort(containerIp, s.Caps)
	u := &url.URL{Scheme: "http", Host: hostPort.Selenium, Path: s.Service.Path}
	log.Printf("[%d] [SELENIUM_URL] [%s] [%s]", requestID, containerInstanceId, u.String())

	if err := waitForEndpointReady(u.String(), s.StartupTimeout); err != nil {
		s.deleteContainerInstance(ociClient, containerInstanceId, requestID)
	}
	ss := StartedService{
		Orchestrator: "aws-ecs",
		Url:          u,
		Pod: &session.Pod{
			ID:            containerInstanceId,
			Name:          containerInstanceDisplayName,
			ContainerName: containerDisplayName,
			ContainerId:   *getContainerResp.Containers[0].ContainerId,
			Namespace:     "",
			IPAddress:     containerIp,
			Configuration: map[string]string{},
		},
		HostPort: hostPort,
		Cancel: func() {
			defer s.deleteContainerInstance(ociClient, containerInstanceId, requestID)
		},
	}
	return &ss, nil
}

func (s *OCIContainerInstancesService) getEnvVars(service ServiceBase, caps session.Caps) map[string]string {
	env := getEnv(service, caps)
	envVars := map[string]string{}
	for _, s := range env {
		entry := strings.SplitN(s, "=", 2)
		envVars[entry[0]] = entry[1]
	}
	return envVars
}

func (s *OCIContainerInstancesService) deleteContainerInstance(ociClient containerinstances.ContainerInstanceClient, containerInstanceId string, requestID uint64) {
	log.Printf("[%d] [deleteContainerInstance] [%s]", requestID, containerInstanceId)
	ctx := context.Background()
	_, err := ociClient.DeleteContainerInstance(ctx, containerinstances.DeleteContainerInstanceRequest{
		ContainerInstanceId: &containerInstanceId,
	})
	if err != nil {
		log.Printf("[%d] [deleteContainerInstance] [error] [%s]", requestID, err)
	}
}
