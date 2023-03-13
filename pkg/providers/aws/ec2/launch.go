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
	Metadata               defsecTypes.Metadata
	Id                     defsecTypes.StringValue
	DefaultVersion         defsecTypes.IntValue
	Instance               Instance
	LaunchTemplateVersions []LaunchTemplateVersion
}

func (i *LaunchConfiguration) RequiresIMDSToken() bool {
	return i.MetadataOptions.HttpTokens.EqualTo("required")
}

func (i *LaunchConfiguration) HasHTTPEndpointDisabled() bool {
	return i.MetadataOptions.HttpEndpoint.EqualTo("disabled")
}

type AccountAttribute struct {
	Metadata        defsecTypes.Metadata
	AttributeName   defsecTypes.StringValue
	AttributeValues []defsecTypes.StringValue
}

type NetworkInterface struct {
	Metadata defsecTypes.Metadata
	Id       defsecTypes.StringValue
	Status   defsecTypes.StringValue
}

type LaunchTemplateVersion struct {
	Metadata           defsecTypes.Metadata
	VersionNumber      defsecTypes.IntValue
	LaunchTemplateData LaunchTemplateData
}

type LaunchTemplateData struct {
	Metadata defsecTypes.Metadata
	ImageId  defsecTypes.StringValue
}
