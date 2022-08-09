package elb

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type ELB struct {
	LoadBalancers []LoadBalancer
}

const (
	TypeApplication = "application"
	TypeGateway     = "gateway"
	TypeNetwork     = "network"
	TypeClassic     = "classic"
)

type LoadBalancer struct {
	types2.Metadata
	Type                    types2.StringValue
	DropInvalidHeaderFields types2.BoolValue
	Internal                types2.BoolValue
	Listeners               []Listener
}

type Listener struct {
	types2.Metadata
	Protocol       types2.StringValue
	TLSPolicy      types2.StringValue
	DefaultActions []Action
}

type Action struct {
	types2.Metadata
	Type types2.StringValue
}
