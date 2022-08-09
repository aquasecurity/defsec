package ec2

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type LaunchConfiguration struct {
	types2.Metadata
	Name              types2.StringValue
	AssociatePublicIP types2.BoolValue
	RootBlockDevice   *BlockDevice
	EBSBlockDevices   []*BlockDevice
	MetadataOptions   MetadataOptions
	UserData          types2.StringValue
}

type LaunchTemplate struct {
	types2.Metadata
	Instance
}

func (i *LaunchConfiguration) RequiresIMDSToken() bool {
	return i.MetadataOptions.HttpTokens.EqualTo("required")
}

func (i *LaunchConfiguration) HasHTTPEndpointDisabled() bool {
	return i.MetadataOptions.HttpEndpoint.EqualTo("disabled")
}
