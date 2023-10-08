package ec2

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Subnet struct {
	Metadata                defsecTypes.Metadata
	MapPublicIpOnLaunch     defsecTypes.BoolValue
	SubnetId                defsecTypes.StringValue
	VPcId                   defsecTypes.StringValue
	CidrBlock               defsecTypes.StringValue
	AvailableIpAddressCount defsecTypes.IntValue
}

type Image struct {
	Metadata        defsecTypes.Metadata
	ImageId         defsecTypes.StringValue
	DeprecationTime defsecTypes.StringValue
	Public          defsecTypes.BoolValue
	EbsBlockDecive  []EbsBlockDecive
}

type EbsBlockDecive struct {
	Metadata   defsecTypes.Metadata
	Encryption defsecTypes.BoolValue
}

type ResourceTags struct {
	Metadata   defsecTypes.Metadata
	Resourceid defsecTypes.StringValue
	Key        defsecTypes.StringValue
	Value      defsecTypes.StringValue
}

type FlowLog struct {
	Metadata   defsecTypes.Metadata
	Id         defsecTypes.StringValue
	ResourceId defsecTypes.StringValue
}
