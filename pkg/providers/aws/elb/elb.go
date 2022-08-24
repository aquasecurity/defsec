package elb

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
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
	defsecTypes.Metadata
	Type                    defsecTypes.StringValue
	DropInvalidHeaderFields defsecTypes.BoolValue
	Internal                defsecTypes.BoolValue
	Listeners               []Listener
}

type Listener struct {
	defsecTypes.Metadata
	Protocol       defsecTypes.StringValue
	TLSPolicy      defsecTypes.StringValue
	DefaultActions []Action
}

type Action struct {
	defsecTypes.Metadata
	Type defsecTypes.StringValue
}
