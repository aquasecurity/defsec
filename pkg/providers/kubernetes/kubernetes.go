package kubernetes

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type Kubernetes struct {
	NetworkPolicies []NetworkPolicy
}

type NetworkPolicy struct {
	types2.Metadata
	Spec Spec
}

type Spec struct {
	types2.Metadata
	Egress  Egress
	Ingress Ingress
}

type Egress struct {
	types2.Metadata
	Ports            []Port
	DestinationCIDRs []types2.StringValue
}

type Ingress struct {
	types2.Metadata
	Ports       []Port
	SourceCIDRs []types2.StringValue
}

type Port struct {
	types2.Metadata
	Number   types2.StringValue // e.g. "http" or "80"
	Protocol types2.StringValue
}
