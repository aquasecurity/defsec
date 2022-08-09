package openstack

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type Networking struct {
	SecurityGroups []SecurityGroup
}

type SecurityGroup struct {
	types2.Metadata
	Name        types2.StringValue
	Description types2.StringValue
	Rules       []SecurityGroupRule
}

// SecurityGroupRule describes https://registry.terraform.io/providers/terraform-provider-openstack/openstack/latest/docs/resources/networking_secgroup_rule_v2
type SecurityGroupRule struct {
	types2.Metadata
	IsIngress types2.BoolValue
	EtherType types2.IntValue    // 4 or 6 for ipv4/ipv6
	Protocol  types2.StringValue // e.g. tcp
	PortMin   types2.IntValue
	PortMax   types2.IntValue
	CIDR      types2.StringValue
}
