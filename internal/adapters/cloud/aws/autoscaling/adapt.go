package autoscaling

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	api "github.com/aws/aws-sdk-go-v2/service/autoscaling"
	aatypes "github.com/aws/aws-sdk-go-v2/service/autoscaling/types"

	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/autoscaling"
	"github.com/aquasecurity/defsec/pkg/state"
	"github.com/aquasecurity/defsec/pkg/types"
)

type adapter struct {
	*aws.RootAdapter
	api *api.Client
}

func init() {
	aws.RegisterServiceAdapter(&adapter{})
}

func (a *adapter) Provider() string {
	return "aws"
}

func (a *adapter) Name() string {
	return "autoscaling"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {
	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())

	var err error
	state.AWS.Autoscaling.AutoscalingGroupsList, err = a.getAutoscaling()
	if err != nil {
		return err
	}

	state.AWS.Autoscaling.LaunchConfigurations, err = a.getLaunchConfigurations()
	if err != nil {
		return err
	}

	state.AWS.Autoscaling.NotificationConfigurations, err = a.getNotificationConfigurations()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getAutoscaling() ([]autoscaling.AutoscalingGroupsList, error) {
	a.Tracker().SetServiceLabel(" Availability Zones List...")

	var input api.DescribeAutoScalingGroupsInput
	var autoscalingapi []aatypes.AutoScalingGroup

	for {
		output, err := a.api.DescribeAutoScalingGroups(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		autoscalingapi = append(autoscalingapi, output.AutoScalingGroups...)

		a.Tracker().SetTotalResources(len(autoscalingapi))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken

	}
	a.Tracker().SetServiceLabel("Adapting analyzers...")
	return concurrency.Adapt(autoscalingapi, a.RootAdapter, a.adaptautoscaling), nil

}

func (a *adapter) adaptautoscaling(autoscalingapi aatypes.AutoScalingGroup) (*autoscaling.AutoscalingGroupsList, error) {

	if autoscalingapi.AutoScalingGroupARN == nil {
		return nil, fmt.Errorf("missing arn")
	}
	parsed, err := arn.Parse(*autoscalingapi.AutoScalingGroupARN)
	if err != nil {
		return nil, fmt.Errorf("invalid arn: %w", err)
	}
	if parsed.Region != a.Region() {
		return nil, nil // skip other regions
	}

	metadata := a.CreateMetadataFromARN(*autoscalingapi.AutoScalingGroupARN)
	var name string
	if autoscalingapi.AutoScalingGroupName != nil {
		name = *autoscalingapi.AutoScalingGroupName
	}

	var AVZone []types.StringValue
	for _, av := range autoscalingapi.AvailabilityZones {
		AVZone = append(AVZone, types.String(av, metadata))
	}

	var InsList []autoscaling.InstanceList
	for _, il := range autoscalingapi.Instances {
		var instanceId string
		if il.InstanceId != nil {
			instanceId = *il.InstanceId
		}

		InsList = append(InsList, autoscaling.InstanceList{
			Metadata:   metadata,
			InstanceId: types.String(instanceId, metadata),
		})
	}

	var HCheckType string
	if autoscalingapi.HealthCheckType != nil {
		HCheckType = *autoscalingapi.HealthCheckType
	}

	var LBNames []types.StringValue
	for _, LBN := range autoscalingapi.LoadBalancerNames {
		LBNames = append(LBNames, types.String(LBN, metadata))
	}

	var ASGArn string
	if autoscalingapi.AutoScalingGroupARN != nil {
		ASGArn = *autoscalingapi.AutoScalingGroupARN
	}

	var DefCooldown int32
	if autoscalingapi.DefaultCooldown != nil {
		DefCooldown = *autoscalingapi.DefaultCooldown
	}

	var SusProcesses []autoscaling.SuspendedProcesses
	for range autoscalingapi.SuspendedProcesses {

		SusProcesses = append(SusProcesses, autoscaling.SuspendedProcesses{
			Metadata: metadata,
		})
	}

	var Tag []autoscaling.Tags
	for _, tr := range autoscalingapi.Tags {
		var resourceid string
		if tr.ResourceId != nil {
			resourceid = *tr.ResourceId
		}

		Tag = append(Tag, autoscaling.Tags{
			Metadata:   metadata,
			ResourceId: types.String(resourceid, metadata),
		})

	}

	var Launchconfigname string
	if autoscalingapi.LaunchConfigurationName != nil {
		Launchconfigname = *autoscalingapi.LaunchConfigurationName
	}

	return &autoscaling.AutoscalingGroupsList{
		Metadata:                metadata,
		Name:                    types.String(name, metadata),
		AvailabilityZone:        AVZone,
		Instances:               InsList,
		HealthCheckType:         types.String(HCheckType, metadata),
		LoadBalancerNames:       LBNames,
		AutoScalingGroupARN:     types.String(ASGArn, metadata),
		DefaultCooldown:         types.IntFromInt32(DefCooldown, metadata),
		LaunchConfigurationName: types.String(Launchconfigname, metadata),
		SuspendedProcesses:      SusProcesses,
		Tags:                    Tag,
	}, nil

}

func (a *adapter) getLaunchConfigurations() ([]autoscaling.LaunchConfigurations, error) {
	a.Tracker().SetServiceLabel("Launch Configurations...")

	var input api.DescribeLaunchConfigurationsInput
	var lauchconfigapi []aatypes.LaunchConfiguration

	for {
		output, err := a.api.DescribeLaunchConfigurations(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		lauchconfigapi = append(lauchconfigapi, output.LaunchConfigurations...)

		a.Tracker().SetTotalResources(len(lauchconfigapi))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken

	}
	a.Tracker().SetServiceLabel("Adapting LaunchConfiguration...")
	return concurrency.Adapt(lauchconfigapi, a.RootAdapter, a.adaptlaunchconfiguration), nil

}

func (a *adapter) adaptlaunchconfiguration(lauchconfigapi aatypes.LaunchConfiguration) (*autoscaling.LaunchConfigurations, error) {

	metadata := a.CreateMetadataFromARN(*lauchconfigapi.LaunchConfigurationARN)

	var imgId string
	if lauchconfigapi.ImageId != nil {
		imgId = *lauchconfigapi.ImageId
	}

	var usrData string
	if lauchconfigapi.UserData != nil {
		usrData = *lauchconfigapi.UserData
	}

	var iamInstProf string
	if lauchconfigapi.IamInstanceProfile != nil {
		iamInstProf = *lauchconfigapi.IamInstanceProfile
	}

	var launchCfgName string
	if lauchconfigapi.LaunchConfigurationName != nil {
		launchCfgName = *lauchconfigapi.LaunchConfigurationName
	}

	var launchCfgArn string
	if lauchconfigapi.LaunchConfigurationARN != nil {
		launchCfgArn = *lauchconfigapi.LaunchConfigurationARN
	}

	return &autoscaling.LaunchConfigurations{
		Metadata:                metadata,
		ImageId:                 types.String(imgId, metadata),
		UserData:                types.String(usrData, metadata),
		IamInstanceProfile:      types.String(iamInstProf, metadata),
		LaunchConfigurationName: types.String(launchCfgName, metadata),
		LaunchConfigurationARN:  types.String(launchCfgArn, metadata),
	}, nil

}

func (a *adapter) getNotificationConfigurations() ([]autoscaling.NotificationConfigurations, error) {
	a.Tracker().SetServiceLabel("Notificaiton Configurations...")

	var input api.DescribeNotificationConfigurationsInput
	var notificationconfigapi []aatypes.NotificationConfiguration

	for {
		output, err := a.api.DescribeNotificationConfigurations(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		notificationconfigapi = append(notificationconfigapi, output.NotificationConfigurations...)

		a.Tracker().SetTotalResources(len(notificationconfigapi))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken

	}
	a.Tracker().SetServiceLabel("Adapting LaunchConfiguration...")
	return concurrency.Adapt(notificationconfigapi, a.RootAdapter, a.adaptnotificationconfiguration), nil

}

func (a *adapter) adaptnotificationconfiguration(notificationconfigapi aatypes.NotificationConfiguration) (*autoscaling.NotificationConfigurations, error) {

	metadata := a.CreateMetadataFromARN(*notificationconfigapi.TopicARN)

	var ASGname string
	if notificationconfigapi.AutoScalingGroupName != nil {
		ASGname = *notificationconfigapi.AutoScalingGroupName
	}

	return &autoscaling.NotificationConfigurations{
		Metadata:             metadata,
		AutoScalingGroupName: types.String(ASGname, metadata),
	}, nil

}
