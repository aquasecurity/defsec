package ec2

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type NetworkACL struct {
	Metadata      defsecTypes.Metadata
	Rules         []NetworkACLRule
	Entries       []Entries
	IsDefaultRule defsecTypes.BoolValue
}

type SecurityGroup struct {
	Metadata     defsecTypes.Metadata
	GroupName    defsecTypes.StringValue
	GroupId      defsecTypes.StringValue
	IsDefault    defsecTypes.BoolValue
	Description  defsecTypes.StringValue
	IngressRules []SecurityGroupRule
	EgressRules  []SecurityGroupRule
	VPCID        defsecTypes.StringValue
	Tags         []Tags
}

type SecurityGroupRule struct {
	Metadata     defsecTypes.Metadata
	ToPort       defsecTypes.IntValue
	FromPort     defsecTypes.IntValue
	Description  defsecTypes.StringValue
	IpProtocol   defsecTypes.StringValue
	CIDRs        []defsecTypes.StringValue
	UserGroupIds []defsecTypes.StringValue
}

type VPC struct {
	Metadata        defsecTypes.Metadata
	ID              defsecTypes.StringValue
	IsDefault       defsecTypes.BoolValue
	SecurityGroups  []SecurityGroup
	FlowLogsEnabled defsecTypes.BoolValue
	Tags            []Tags
}

type VpcEndPoint struct {
	Metadata       defsecTypes.Metadata
	ID             defsecTypes.StringValue
	Type           defsecTypes.StringValue
	PolicyDocument defsecTypes.StringValue
	SubnetIds      []defsecTypes.StringValue
}

type VpcEndPointService struct {
	Metadata                          defsecTypes.Metadata
	ServiceId                         defsecTypes.StringValue
	Owner                             defsecTypes.StringValue
	VpcEPSPermissionAllowedPrincipals []AllowedPricipal
}

type AllowedPricipal struct {
	Metadata defsecTypes.Metadata
}

const (
	TypeIngress = "ingress"
	TypeEgress  = "egress"
)

const (
	ActionAllow = "allow"
	ActionDeny  = "deny"
)

type NetworkACLRule struct {
	Metadata defsecTypes.Metadata
	Type     defsecTypes.StringValue
	Action   defsecTypes.StringValue
	Protocol defsecTypes.StringValue
	CIDRs    []defsecTypes.StringValue
}

type Entries struct {
	Metadata   defsecTypes.Metadata
	Egress     defsecTypes.BoolValue
	RuleAction defsecTypes.StringValue
	PortRange  PortRange
}

type PortRange struct {
	Metadata defsecTypes.Metadata
	To       defsecTypes.IntValue
	From     defsecTypes.IntValue
}

type VpcPeeringConnection struct {
	Metadata               defsecTypes.Metadata
	VpcPeeringConnectionId defsecTypes.StringValue
	AccepterVpcInfo        VpcInfo
	RequesterVpcInfo       VpcInfo
}

type VpcInfo struct {
	Metadata  defsecTypes.Metadata
	VPCId     defsecTypes.StringValue
	OwnerId   defsecTypes.StringValue
	CidrBlock defsecTypes.StringValue
}
