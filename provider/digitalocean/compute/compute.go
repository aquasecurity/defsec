package compute

import "github.com/aquasecurity/defsec/types"

type Compute struct {
	types.Metadata
	Firewalls          []Firewall
	LoadBalancers      []LoadBalancer
	Droplets           []Droplet
	KubernetesClusters []KubernetesCluster
}

type Firewall struct {
	types.Metadata
	OutboundRules []OutboundFirewallRule
	InboundRules  []InboundFirewallRule
}

type KubernetesCluster struct {
	types.Metadata
	SurgeUpgrade types.BoolValue
	AutoUpgrade  types.BoolValue
}

type LoadBalancer struct {
	types.Metadata
	ForwardingRules []ForwardingRule
}

type ForwardingRule struct {
	types.Metadata
	EntryProtocol types.StringValue
}

type OutboundFirewallRule struct {
	types.Metadata
	DestinationAddresses []types.StringValue
}

type InboundFirewallRule struct {
	types.Metadata
	SourceAddresses []types.StringValue
}

type Droplet struct {
	types.Metadata
	SSHKeys []types.StringValue
}

func (kc KubernetesCluster) GetMetadata() *types.Metadata {
	return &kc.Metadata
}

func (d Droplet) GetMetadata() *types.Metadata {
	return &d.Metadata
}

func (d Droplet) GetRawValue() interface{} {
	return nil
}
