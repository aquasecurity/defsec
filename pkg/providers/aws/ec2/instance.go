package ec2

import (
	"github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/aws/vpc"
	"github.com/owenrumney/squealer/pkg/squealer"
)

type Instance struct {
	types.Metadata
	MetadataOptions MetadataOptions
	UserData        types.StringValue
	SecurityGroups  []vpc.SecurityGroup
	RootBlockDevice *BlockDevice
	EBSBlockDevices []*BlockDevice
}

type BlockDevice struct {
	types.Metadata
	Encrypted types.BoolValue
}

type MetadataOptions struct {
	types.Metadata
	HttpTokens   types.StringValue
	HttpEndpoint types.StringValue
}

func NewInstance(metadata types.Metadata) Instance {
	return Instance{
		Metadata: metadata,
		MetadataOptions: MetadataOptions{
			Metadata:     metadata,
			HttpTokens:   types.StringDefault("optional", metadata),
			HttpEndpoint: types.StringDefault("enabled", metadata),
		},
		UserData:        types.StringDefault("", metadata),
		SecurityGroups:  []vpc.SecurityGroup{},
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
