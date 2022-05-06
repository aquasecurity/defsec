package emr

import (
	"github.com/aquasecurity/defsec/internal/types"
)

type EMR struct {
	Clusters              []Cluster
	SecurityConfiguration []SecurityConfiguration
}

type Cluster struct {
	types.Metadata
	Settings ClusterSettings
}

// type SecurityConfiguration struct {
// 	types.Metadata
// 	Settings SecurityConfigurationSettings
// }

type SecurityConfiguration struct {
	types.Metadata
	configuration types.StringValue
}

type ClusterSettings struct {
	InstanceType        types.StringValue
	InstanceCount       types.IntValue
	MasterInstanceType  types.StringValue
	MasterInstanceCount types.IntValue
	CoreInstanceType    types.StringValue
	CoreInstanceCount   types.IntValue
	TaskInstanceType    types.StringValue
	TaskInstanceCount   types.IntValue
	EMRVersion          types.StringValue
	ReleaseLabel        types.StringValue
	Variables           map[string]types.StringValue
	Tags                map[string]types.StringValue
	// BootstrapActions         []BootstrapAction
	// Steps                    []Step
	Environment              map[string]types.StringValue
	AutoScalingRole          types.StringValue
	ServiceRole              types.StringValue
	VariablesFile            types.StringValue
	CustomAmiId              types.StringValue
	CustomAmiName            types.StringValue
	CustomAmiDescription     types.StringValue
	CustomAmiExecutableUsers types.StringValue
}
