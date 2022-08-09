package ec2

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
	"github.com/owenrumney/squealer/pkg/squealer"
)

type Instance struct {
	types2.Metadata
	MetadataOptions MetadataOptions
	UserData        types2.StringValue
	SecurityGroups  []SecurityGroup
	RootBlockDevice *BlockDevice
	EBSBlockDevices []*BlockDevice
}

type BlockDevice struct {
	types2.Metadata
	Encrypted types2.BoolValue
}

type MetadataOptions struct {
	types2.Metadata
	HttpTokens   types2.StringValue
	HttpEndpoint types2.StringValue
}

func NewInstance(metadata types2.Metadata) Instance {
	return Instance{
		Metadata: metadata,
		MetadataOptions: MetadataOptions{
			Metadata:     metadata,
			HttpTokens:   types2.StringDefault("optional", metadata),
			HttpEndpoint: types2.StringDefault("enabled", metadata),
		},
		UserData:        types2.StringDefault("", metadata),
		SecurityGroups:  []SecurityGroup{},
		RootBlockDevice: nil,
		EBSBlockDevices: nil,
	}
}

func (i *Instance) RequiresIMDSToken() bool {
	return i.MetadataOptions.HttpTokens.EqualTo("required")
}

func (i *Instance) HasHTTPEndpointDisabled() bool {
	return i.MetadataOptions.HttpEndpoint.EqualTo("disabled")
}

func (i *Instance) HasSensitiveInformationInUserData() bool {
	scanner := squealer.NewStringScanner()
	return scanner.Scan(i.UserData.Value()).TransgressionFound
}
