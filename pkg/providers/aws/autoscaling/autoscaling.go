package autoscaling

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Autoscaling struct {
	AutoscalingGroupsList      []AutoscalingGroupsList
	NotificationConfigurations []NotificationConfigurations
	LaunchConfigurations       []LaunchConfigurations
}

type AutoscalingGroupsList struct {
	Metadata                defsecTypes.Metadata
	Name                    defsecTypes.StringValue
	AvailabilityZone        []defsecTypes.StringValue
	Instances               []InstanceList
	HealthCheckType         defsecTypes.StringValue
	LoadBalancerNames       []defsecTypes.StringValue
	AutoScalingGroupARN     defsecTypes.StringValue
	DefaultCooldown         defsecTypes.IntValue
	SuspendedProcesses      []SuspendedProcesses
	Tags                    []Tags
	LaunchConfigurationName defsecTypes.StringValue
}

type InstanceList struct {
	Metadata   defsecTypes.Metadata
	InstanceId defsecTypes.StringValue
}

type NotificationConfigurations struct {
	Metadata             defsecTypes.Metadata
	AutoScalingGroupName defsecTypes.StringValue
}

type LaunchConfigurations struct {
	Metadata                defsecTypes.Metadata
	ImageId                 defsecTypes.StringValue
	UserData                defsecTypes.StringValue
	IamInstanceProfile      defsecTypes.StringValue
	LaunchConfigurationName defsecTypes.StringValue
	LaunchConfigurationARN  defsecTypes.StringValue
}

type SuspendedProcesses struct {
	Metadata defsecTypes.Metadata
}

type Tags struct {
	Metadata   defsecTypes.Metadata
	ResourceId defsecTypes.StringValue
}
