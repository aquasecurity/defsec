package ec2

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type LaunchConfiguration struct {
	Metadata          defsecTypes.Metadata
	Name              defsecTypes.StringValue
	AssociatePublicIP defsecTypes.BoolValue
	RootBlockDevice   *BlockDevice
	EBSBlockDevices   []*BlockDevice
	MetadataOptions   MetadataOptions
	UserData          defsecTypes.StringValue
}

type LaunchTemplate struct {
	Metadata defsecTypes.Metadata
	Instance
}

func (i *LaunchConfiguration) RequiresIMDSToken() bool {
	return i.MetadataOptions.HttpTokens.EqualTo("required")
}

func (i *LaunchConfiguration) HasHTTPEndpointDisabled() bool {
	return i.MetadataOptions.HttpEndpoint.EqualTo("disabled")
}
