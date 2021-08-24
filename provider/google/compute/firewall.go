package compute

import "github.com/aquasecurity/defsec/definition"

type Firewall struct {
	*definition.Metadata
	IngressRules []IngressRule
	EgressRules  []EgressRule
}

type FirewallRule struct {
	*definition.Metadata
	Enforced definition.BoolValue
	IsAllow  definition.BoolValue
}

type IngressRule struct {
	*definition.Metadata
	FirewallRule
	Source definition.StringValue
}

type EgressRule struct {
	*definition.Metadata
	FirewallRule
	Destination definition.StringValue
}
