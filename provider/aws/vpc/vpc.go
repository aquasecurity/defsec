package vpc

import "github.com/aquasecurity/defsec/types"

type VPC struct {
	DefaultVPCs     []DefaultVPC
	SecurityGroups  []SecurityGroup
	NetworkACLRules []NetworkACLRule
}

type SecurityGroup struct {
	types.Metadata
	Description types.StringValue
	Rules       []SecurityGroupRule
}

type SecurityGroupRule struct {
	Description types.StringValue
	CIDRs       []types.StringValue
	Type        types.StringValue
}

type DefaultVPC struct {
	types.Metadata
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
	types.Metadata
	Type     types.StringValue
	Action   types.StringValue
	Protocol types.StringValue
	CIDRs    []types.StringValue
}

func (v *DefaultVPC) GetMetadata() *types.Metadata {
	return &v.Metadata
}

func (v *DefaultVPC) GetRawValue() interface{} {
	return nil
}
