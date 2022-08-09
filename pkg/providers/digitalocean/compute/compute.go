package compute

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type Compute struct {
	Firewalls          []Firewall
	LoadBalancers      []LoadBalancer
	Droplets           []Droplet
	KubernetesClusters []KubernetesCluster
}

type Firewall struct {
	types2.Metadata
	OutboundRules []OutboundFirewallRule
	InboundRules  []InboundFirewallRule
}

type KubernetesCluster struct {
	types2.Metadata
	SurgeUpgrade types2.BoolValue
	AutoUpgrade  types2.BoolValue
}

type LoadBalancer struct {
	types2.Metadata
	ForwardingRules []ForwardingRule
}

type ForwardingRule struct {
	types2.Metadata
	EntryProtocol types2.StringValue
}

type OutboundFirewallRule struct {
	types2.Metadata
	DestinationAddresses []types2.StringValue
}

type InboundFirewallRule struct {
	types2.Metadata
	SourceAddresses []types2.StringValue
}

type Droplet struct {
	types2.Metadata
	SSHKeys []types2.StringValue
}
