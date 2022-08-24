package compute

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Firewall struct {
	defsecTypes.Metadata
	Name         defsecTypes.StringValue
	IngressRules []IngressRule
	EgressRules  []EgressRule
	SourceTags   []defsecTypes.StringValue
	TargetTags   []defsecTypes.StringValue
}

type FirewallRule struct {
	defsecTypes.Metadata
	Enforced defsecTypes.BoolValue
	IsAllow  defsecTypes.BoolValue
	Protocol defsecTypes.StringValue
	Ports    []defsecTypes.IntValue
}

type IngressRule struct {
	defsecTypes.Metadata
	FirewallRule
	SourceRanges []defsecTypes.StringValue
}

type EgressRule struct {
	defsecTypes.Metadata
	FirewallRule
	DestinationRanges []defsecTypes.StringValue
}
