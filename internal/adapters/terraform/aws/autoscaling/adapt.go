package autoscaling

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/autoscaling"
	"github.com/aquasecurity/defsec/pkg/terraform"
	"github.com/aquasecurity/defsec/pkg/types"
)

func Adapt(modules terraform.Modules) autoscaling.Autoscaling {
	return autoscaling.Autoscaling{
		AutoscalingGroupsList:      adaptAutoscalings(modules),
		NotificationConfigurations: adaptNotificationConfigurations(modules),
		LaunchConfigurations:       adaptLaunchConfigurations(modules),
	}
}

func adaptAutoscalings(modules terraform.Modules) []autoscaling.AutoscalingGroupsList {
	var AvaiabilityZone []autoscaling.AutoscalingGroupsList
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_autoscaling_group") {
			AvaiabilityZone = append(AvaiabilityZone, adaptAutoscaling(resource, module))
		}
	}
	return AvaiabilityZone
}

func adaptNotificationConfigurations(modules terraform.Modules) []autoscaling.NotificationConfigurations {
	var NotificationConfig []autoscaling.NotificationConfigurations
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_autoscaling_notification") {
			NotificationConfig = append(NotificationConfig, adaptNotificationConfiguration(resource, module))
		}
	}
	return NotificationConfig
}

func adaptLaunchConfigurations(modules terraform.Modules) []autoscaling.LaunchConfigurations {
	var LaunchConfig []autoscaling.LaunchConfigurations
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_launch_configuration") {
			LaunchConfig = append(LaunchConfig, adaptLaunchConfiguration(resource, module))
		}
	}
	return LaunchConfig
}

func adaptAutoscaling(resource *terraform.Block, module *terraform.Module) autoscaling.AutoscalingGroupsList {
	nameAttr := resource.GetAttribute("name")
	nameVal := nameAttr.AsStringValueOrDefault("", resource)

	var AZones []types.StringValue
	AZAttr := resource.GetAttribute("availability_zones")
	for _, AZ := range AZAttr.AsStringValues() {
		AZones = append(AZones, AZ)
	}

	HCTAttr := resource.GetAttribute("health_check_type")
	HCTVal := HCTAttr.AsStringValueOrDefault("", resource)

	var LBNames []types.StringValue
	LBNAttr := resource.GetAttribute("load_balancers")
	for _, LBN := range LBNAttr.AsStringValues() {
		LBNames = append(LBNames, LBN)
	}

	ASGArnAttr := resource.GetAttribute("arn")
	ASGArnVal := ASGArnAttr.AsStringValueOrDefault("", resource)

	DefaultCooldownAttr := resource.GetAttribute("default_cooldown")
	DefaultCooldownVal := DefaultCooldownAttr.AsIntValueOrDefault(0, resource)

	LaunchConfigurationNameAttr := resource.GetAttribute("launch_configuration")
	LaunchConfigurationNameVal := LaunchConfigurationNameAttr.AsStringValueOrDefault("", resource)

	var suspendedprocess []autoscaling.SuspendedProcesses
	for _, susBlock := range resource.GetBlocks("suspended_processes") {

		suspendedprocess = append(suspendedprocess, autoscaling.SuspendedProcesses{
			Metadata: susBlock.GetMetadata(),
		})
	}

	var Tags []autoscaling.Tags
	tagsRes := resource.GetBlocks("tags")
	for _, tagRes := range tagsRes {

		Tags = append(Tags, autoscaling.Tags{
			Metadata:   tagRes.GetMetadata(),
			ResourceId: types.StringDefault("", tagRes.GetMetadata()),
		})
	}

	return autoscaling.AutoscalingGroupsList{
		Metadata:                resource.GetMetadata(),
		Name:                    nameVal,
		AvailabilityZone:        AZones,
		Instances:               nil,
		HealthCheckType:         HCTVal,
		LoadBalancerNames:       LBNames,
		AutoScalingGroupARN:     ASGArnVal,
		DefaultCooldown:         DefaultCooldownVal,
		SuspendedProcesses:      suspendedprocess,
		Tags:                    Tags,
		LaunchConfigurationName: LaunchConfigurationNameVal,
	}
}

func adaptNotificationConfiguration(resource *terraform.Block, module *terraform.Module) autoscaling.NotificationConfigurations {
	asgnameAttr := resource.GetAttribute("group_names")
	asgnameVal := asgnameAttr.AsStringValueOrDefault("", resource)

	return autoscaling.NotificationConfigurations{
		Metadata:             resource.GetMetadata(),
		AutoScalingGroupName: asgnameVal,
	}
}

func adaptLaunchConfiguration(resource *terraform.Block, module *terraform.Module) autoscaling.LaunchConfigurations {

	imageIdAttr := resource.GetAttribute("image_id")
	imageIdVal := imageIdAttr.AsStringValueOrDefault("", resource)

	userDataAttr := resource.GetAttribute("user_data")
	userDataVal := userDataAttr.AsStringValueOrDefault("", resource)

	iamInstanceProfileAttr := resource.GetAttribute("iam_instance_profile")
	iamInstanceProfileVal := iamInstanceProfileAttr.AsStringValueOrDefault("", resource)

	launchConfigNameAttr := resource.GetAttribute("name")
	launchConfigNameVal := launchConfigNameAttr.AsStringValueOrDefault("", resource)

	launchConfigArnAttr := resource.GetAttribute("arn")
	launchConfigArnVal := launchConfigArnAttr.AsStringValueOrDefault("", resource)

	return autoscaling.LaunchConfigurations{
		Metadata:                resource.GetMetadata(),
		ImageId:                 imageIdVal,
		UserData:                userDataVal,
		IamInstanceProfile:      iamInstanceProfileVal,
		LaunchConfigurationName: launchConfigNameVal,
		LaunchConfigurationARN:  launchConfigArnVal,
	}
}
