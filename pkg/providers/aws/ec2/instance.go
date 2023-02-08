package ec2

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	"github.com/owenrumney/squealer/pkg/squealer"
)

type Instance struct {
	Metadata              defsecTypes.Metadata
	MetadataOptions       MetadataOptions
	CPUOptions            CPUOptions
	UserData              defsecTypes.StringValue
	VPCId                 defsecTypes.StringValue
	ImageId               defsecTypes.StringValue
	PublicIpAddress       defsecTypes.StringValue
	SubnetId              defsecTypes.StringValue
	InstanceId            defsecTypes.StringValue
	InstanceType          defsecTypes.StringValue
	InstanceLifecycle     defsecTypes.StringValue
	IamInstanceProfile    defsecTypes.StringValue
	StateName             defsecTypes.StringValue
	MonitoringState       defsecTypes.BoolValue
	KeyName               defsecTypes.StringValue
	SpotInstanceRequestId defsecTypes.StringValue
	Tags                  []Tags
	SecurityGroups        []SecurityGroup
	SecurityGroupIds      []defsecTypes.StringValue
	RootBlockDevice       *BlockDevice
	EBSBlockDevices       []*BlockDevice
	NetworkInterfaces     []NetworkInterfaces
}

type BlockDevice struct {
	Metadata  defsecTypes.Metadata
	Encrypted defsecTypes.BoolValue
	VolumeId  defsecTypes.StringValue
}

type MetadataOptions struct {
	Metadata     defsecTypes.Metadata
	HttpTokens   defsecTypes.StringValue
	HttpEndpoint defsecTypes.StringValue
}

type CPUOptions struct {
	Metadata      defsecTypes.Metadata
	CoreCount     defsecTypes.IntValue
	ThreadPerCore defsecTypes.IntValue
}

type NetworkInterfaces struct {
	Metadata defsecTypes.Metadata
}

func NewInstance(metadata defsecTypes.Metadata) *Instance {
	return &Instance{
		Metadata: metadata,
		MetadataOptions: MetadataOptions{
			Metadata:     metadata,
			HttpTokens:   defsecTypes.StringDefault("optional", metadata),
			HttpEndpoint: defsecTypes.StringDefault("enabled", metadata),
		},
		CPUOptions: CPUOptions{
			Metadata:      metadata,
			CoreCount:     defsecTypes.Int(1, metadata),
			ThreadPerCore: defsecTypes.Int(2, metadata),
		},
		UserData:              defsecTypes.StringDefault("", metadata),
		VPCId:                 defsecTypes.StringDefault("", metadata),
		InstanceLifecycle:     defsecTypes.StringDefault("", metadata),
		ImageId:               defsecTypes.StringDefault("", metadata),
		SubnetId:              defsecTypes.StringDefault("", metadata),
		PublicIpAddress:       defsecTypes.StringDefault("", metadata),
		InstanceId:            defsecTypes.StringDefault("", metadata),
		InstanceType:          defsecTypes.StringDefault("", metadata),
		IamInstanceProfile:    defsecTypes.StringDefault("", metadata),
		StateName:             defsecTypes.StringDefault("pending", metadata),
		MonitoringState:       defsecTypes.BoolDefault(false, metadata),
		KeyName:               defsecTypes.StringDefault("", metadata),
		SpotInstanceRequestId: defsecTypes.StringDefault("", metadata),
		SecurityGroups:        []SecurityGroup{},
		SecurityGroupIds:      nil,
		Tags:                  nil,
		RootBlockDevice:       nil,
		EBSBlockDevices:       nil,
		NetworkInterfaces:     nil,
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
