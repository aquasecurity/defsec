package autoscaling

import "github.com/aquasecurity/defsec/types"

type Autoscaling struct {
	LaunchConfigurations []LaunchConfiguration
}

type LaunchConfiguration struct {
	Name              types.StringValue
	AssociatePublicIP types.BoolValue
	RootBlockDevice   BlockDevice
	EBSBlockDevices   []BlockDevice
	UserData          types.StringValue
}

type BlockDevice struct {
	Encrypted types.BoolValue
}
