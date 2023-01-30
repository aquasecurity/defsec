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

func getAvailabilityZone(r *parser.Resource) (AvaiabilityZone []types.StringValue) {

	AvaiabilityZoneList := r.GetProperty("AvailabilityZones")

	if AvaiabilityZoneList.IsNil() || AvaiabilityZoneList.IsNotList() {
		return AvaiabilityZone
	}

	for _, AZ := range AvaiabilityZoneList.AsList() {
		AvaiabilityZone = append(AvaiabilityZone, AZ.AsStringValue())
	}
	return AvaiabilityZone
}

func getLBNames(r *parser.Resource) (LoadBalancerNames []types.StringValue) {

	LBNames := r.GetProperty("LoadBalancerNames")

	if LBNames.IsNil() || LBNames.IsNotList() {
		return LoadBalancerNames
	}

	for _, LBN := range LBNames.AsList() {
		LoadBalancerNames = append(LoadBalancerNames, LBN.AsStringValue())
	}
	return LoadBalancerNames
}

func getSuspendedProcesses(r *parser.Resource) (SuspendedProcesses []autoscaling.SuspendedProcesses) {

	SusProcesses := r.GetProperty("SuspendedProcesses")

	if SusProcesses.IsNil() || SusProcesses.IsNotNil() {
		return SuspendedProcesses
	}

	for _, SP := range SusProcesses.AsList() {
		SuspendedProcesses = append(SuspendedProcesses, autoscaling.SuspendedProcesses{
			Metadata: SP.Metadata(),
		})
	}
	return SuspendedProcesses
}

func getTags(r *parser.Resource) (Tags []autoscaling.Tags) {

	Tag := r.GetProperty("Tags")

	if Tag.IsNil() || Tag.IsNotNil() {
		return Tags
	}

	for _, TG := range Tag.AsList() {
		Tags = append(Tags, autoscaling.Tags{
			Metadata:   TG.Metadata(),
			ResourceId: types.StringDefault("", TG.Metadata()),
		})
	}
	return Tags
}
