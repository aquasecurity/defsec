package compute

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Compute struct {
	Firewalls          []Firewall
	LoadBalancers      []LoadBalancer
	Droplets           []Droplet
	KubernetesClusters []KubernetesCluster
}

type Firewall struct {
	defsecTypes.Metadata
	OutboundRules []OutboundFirewallRule
	InboundRules  []InboundFirewallRule
}

type KubernetesCluster struct {
	defsecTypes.Metadata
	SurgeUpgrade defsecTypes.BoolValue
	AutoUpgrade  defsecTypes.BoolValue
}

type LoadBalancer struct {
	defsecTypes.Metadata
	ForwardingRules []ForwardingRule
}

type ForwardingRule struct {
	defsecTypes.Metadata
	EntryProtocol defsecTypes.StringValue
}

type OutboundFirewallRule struct {
	defsecTypes.Metadata
	DestinationAddresses []defsecTypes.StringValue
}

type InboundFirewallRule struct {
	defsecTypes.Metadata
	SourceAddresses []defsecTypes.StringValue
}

type Droplet struct {
	defsecTypes.Metadata
	SSHKeys []defsecTypes.StringValue
}
