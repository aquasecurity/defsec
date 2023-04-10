package autoscaling

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/autoscaling"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	"github.com/aquasecurity/defsec/pkg/types"
)

func getAutoscalingGroups(ctx parser.FileContext) (groups []autoscaling.AutoscalingGroupsList) {

	autoscalingResources := ctx.GetResourcesByType("AWS::AutoScaling::AutoScalingGroup")

	for _, r := range autoscalingResources {
		ag := autoscaling.AutoscalingGroupsList{
			Metadata:                r.Metadata(),
			Name:                    r.GetStringProperty("AutoScalingGroupName"),
			AvaiabilityZone:         getAvailabilityZone(r),
			Instances:               nil,
			HealthCheckType:         r.GetStringProperty("HealthCheckType"),
			LoadBalancerNames:       getLBNames(r),
			AutoScalingGroupARN:     r.GetStringProperty("AutoScalingGroupARN"),
			DefaultCooldown:         r.GetIntProperty("DefaultCooldown"),
			SuspendedProcesses:      getSuspendedProcesses(r),
			Tags:                    getTags(r),
			LaunchConfigurationName: r.GetStringProperty("LaunchConfigurationName"),
		}

		groups = append(groups, ag)
	}
	return groups
}

func getLaunchConfigurations(ctx parser.FileContext) (launchconfigvals []autoscaling.LaunchConfigurations) {

	launchConfigResources := ctx.GetResourcesByType("AWS::AutoScaling::LaunchConfiguration")

	for _, r := range launchConfigResources {
		lc := autoscaling.LaunchConfigurations{
			Metadata:                r.Metadata(),
			ImageId:                 r.GetStringProperty("ImageId"),
			UserData:                r.GetStringProperty("UserData"),
			IamInstanceProfile:      r.GetStringProperty("IamInstanceProfile"),
			LaunchConfigurationName: r.GetStringProperty("LaunchConfiguraitonName"),
			LaunchConfigurationARN:  r.GetStringProperty("LaunchConfigurationARN"),
		}

		launchconfigvals = append(launchconfigvals, lc)
	}
	return launchconfigvals
}

func getNotificationConfigurations(ctx parser.FileContext) (notificationconfigvals []autoscaling.NotificationConfigurations) {

	notificationConfigResources := ctx.GetResourcesByType("AWS::AutoScaling::NotificationConfiguration")

	for _, r := range notificationConfigResources {
		nc := autoscaling.NotificationConfigurations{
			Metadata:             r.Metadata(),
			AutoScalingGroupName: r.GetStringProperty("AutoScalingGroupName"),
		}
		notificationconfigvals = append(notificationconfigvals, nc)
	}
	return notificationconfigvals
}

func getAvailabilityZone(r *parser.Resource) (avaiabilityZone []types.StringValue) {

	AvaiabilityZoneList := r.GetProperty("AvailabilityZones")

	if AvaiabilityZoneList.IsNil() || AvaiabilityZoneList.IsNotList() {
		return avaiabilityZone
	}

	for _, AZ := range AvaiabilityZoneList.AsList() {
		avaiabilityZone = append(avaiabilityZone, AZ.AsStringValue())
	}
	return avaiabilityZone
}

func getLBNames(r *parser.Resource) (loadBalancerNames []types.StringValue) {

	LBNames := r.GetProperty("LoadBalancerNames")

	if LBNames.IsNil() || LBNames.IsNotList() {
		return loadBalancerNames
	}

	for _, LBN := range LBNames.AsList() {
		loadBalancerNames = append(loadBalancerNames, LBN.AsStringValue())
	}
	return loadBalancerNames
}

func getSuspendedProcesses(r *parser.Resource) (suspendedProcesses []autoscaling.SuspendedProcesses) {

	SusProcesses := r.GetProperty("SuspendedProcesses")

	if SusProcesses.IsNil() || SusProcesses.IsNotNil() {
		return suspendedProcesses
	}

	for _, SP := range SusProcesses.AsList() {
		suspendedProcesses = append(suspendedProcesses, autoscaling.SuspendedProcesses{
			Metadata: SP.Metadata(),
		})
	}
	return suspendedProcesses
}

func getTags(r *parser.Resource) (tags []autoscaling.Tags) {

	Tag := r.GetProperty("Tags")

	if Tag.IsNil() || Tag.IsNotNil() {
		return tags
	}

	for _, TG := range Tag.AsList() {
		tags = append(tags, autoscaling.Tags{
			Metadata:   TG.Metadata(),
			ResourceId: types.StringDefault("", TG.Metadata()),
		})
	}
	return tags
}
