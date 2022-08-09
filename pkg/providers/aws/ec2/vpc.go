package ec2

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type NetworkACL struct {
	defsecTypes.Metadata
	Rules         []NetworkACLRule
	IsDefaultRule defsecTypes.BoolValue
}

type SecurityGroup struct {
	defsecTypes.Metadata
	Description  defsecTypes.StringValue
	IngressRules []SecurityGroupRule
	EgressRules  []SecurityGroupRule
}

type SecurityGroupRule struct {
	defsecTypes.Metadata
	Description defsecTypes.StringValue
	CIDRs       []defsecTypes.StringValue
}

type DefaultVPC struct {
	defsecTypes.Metadata
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
	defsecTypes.Metadata
	Type     defsecTypes.StringValue
	Action   defsecTypes.StringValue
	Protocol defsecTypes.StringValue
	CIDRs    []defsecTypes.StringValue
}
