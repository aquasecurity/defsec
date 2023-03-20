package emr

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type EMR struct {
	Clusters              []Cluster
	SecurityConfiguration []SecurityConfiguration
}

type Cluster struct {
	Metadata      defsecTypes.Metadata
	EC2SubnetId   defsecTypes.StringValue
	LogUri        defsecTypes.StringValue
	InstanceGroup InstanceGroup
	Settings      ClusterSettings
}

type ClusterSettings struct {
	Metadata     defsecTypes.Metadata
	Name         defsecTypes.StringValue
	ReleaseLabel defsecTypes.StringValue
	ServiceRole  defsecTypes.StringValue
}

type SecurityConfiguration struct {
	Metadata      defsecTypes.Metadata
	Name          defsecTypes.StringValue
	Configuration defsecTypes.StringValue
}

type InstanceGroup struct {
	Metadata            defsecTypes.Metadata
	CoreInstanceGroup   Instance
	MasterInstanceGroup Instance
}

type Instance struct {
	Metadata      defsecTypes.Metadata
	InstanceType  defsecTypes.StringValue
	InstanceCount defsecTypes.IntValue
}
