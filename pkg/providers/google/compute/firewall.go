package compute

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type Firewall struct {
	types2.Metadata
	Name         types2.StringValue
	IngressRules []IngressRule
	EgressRules  []EgressRule
	SourceTags   []types2.StringValue
	TargetTags   []types2.StringValue
}

type FirewallRule struct {
	types2.Metadata
	Enforced types2.BoolValue
	IsAllow  types2.BoolValue
	Protocol types2.StringValue
	Ports    []types2.IntValue
}

type IngressRule struct {
	types2.Metadata
	FirewallRule
	SourceRanges []types2.StringValue
}

type EgressRule struct {
	types2.Metadata
	FirewallRule
	DestinationRanges []types2.StringValue
}
