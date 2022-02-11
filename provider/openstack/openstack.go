package openstack

import "github.com/aquasecurity/defsec/types"

type OpenStack struct {
	types.Metadata
	Compute    Compute
	Networking Networking
}

type Compute struct {
	types.Metadata
	Instances []Instance
	Firewall  Firewall
}

type Networking struct {
	types.Metadata
	Direction      types.StringValue
	Ethertype      types.StringValue
	Protocol       types.StringValue
	PortRangeMin   types.IntValue
	PortRangeMax   types.IntValue
	RemoteIPPrefix types.StringValue
}

type Firewall struct {
	types.Metadata
	AllowRules []Rule
	DenyRules  []Rule
}

type Rule struct {
	types.Metadata
	Source          types.StringValue
	Destination     types.StringValue
	SourcePort      types.StringValue
	DestinationPort types.StringValue
	Enabled         types.BoolValue
}

type Instance struct {
	types.Metadata
	AdminPassword types.StringValue
}

func (n Networking) IsIngress() bool {
	return n.Direction.Value() == "ingress"
}
