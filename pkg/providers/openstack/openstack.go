package openstack

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type OpenStack struct {
	Compute    Compute
	Networking Networking
}

type Compute struct {
	Instances []Instance
	Firewall  Firewall
}

type Firewall struct {
	AllowRules []FirewallRule
	DenyRules  []FirewallRule
}

type FirewallRule struct {
	types2.Metadata
	Source          types2.StringValue
	Destination     types2.StringValue
	SourcePort      types2.StringValue
	DestinationPort types2.StringValue
	Enabled         types2.BoolValue
}

type Instance struct {
	types2.Metadata
	AdminPassword types2.StringValue
}
