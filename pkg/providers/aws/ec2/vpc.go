package ec2

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type NetworkACL struct {
	types2.Metadata
	Rules         []NetworkACLRule
	IsDefaultRule types2.BoolValue
}

type SecurityGroup struct {
	types2.Metadata
	Description  types2.StringValue
	IngressRules []SecurityGroupRule
	EgressRules  []SecurityGroupRule
}

type SecurityGroupRule struct {
	types2.Metadata
	Description types2.StringValue
	CIDRs       []types2.StringValue
}

type DefaultVPC struct {
	types2.Metadata
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
	types2.Metadata
	Type     types2.StringValue
	Action   types2.StringValue
	Protocol types2.StringValue
	CIDRs    []types2.StringValue
}
