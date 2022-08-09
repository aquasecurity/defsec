package openstack

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
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
	defsecTypes.Metadata
	Source          defsecTypes.StringValue
	Destination     defsecTypes.StringValue
	SourcePort      defsecTypes.StringValue
	DestinationPort defsecTypes.StringValue
	Enabled         defsecTypes.BoolValue
}

type Instance struct {
	defsecTypes.Metadata
	AdminPassword defsecTypes.StringValue
}
