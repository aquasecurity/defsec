package elb

import "github.com/aquasecurity/defsec/types"

type ELB struct {
	LoadBalancers []LoadBalancer
}

const (
	TypeApplication = "application"
	TypeGateway     = "gateway"
	TypeNetwork     = "network"
)

type LoadBalancer struct {
	*types.Metadata
	Type                    types.StringValue
	DropInvalidHeaderFields types.BoolValue
	Internal                types.BoolValue
	Listeners               []Listener
}

type Listener struct {
	*types.Metadata
	Protocol      types.StringValue
	DefaultAction Action
}

type Action struct {
	Type types.StringValue
}
