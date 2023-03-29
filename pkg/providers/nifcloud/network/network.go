package network

import defsecTypes "github.com/aquasecurity/defsec/pkg/types"

type Network struct {
	ElasticLoadBalancers []ElasticLoadBalancer
	LoadBalancers        []LoadBalancer
	Routers              []Router
	VpnGateways          []VpnGateway
}

type NetworkInterface struct {
	Metadata     defsecTypes.Metadata
	NetworkID    defsecTypes.StringValue
	IsVipNetwork defsecTypes.BoolValue
}
