package compute

import "github.com/aquasecurity/defsec/definition"

type Instance struct {
	*definition.Metadata
	Name              definition.StringValue
	NetworkInterfaces []NetworkInterface
}

type NetworkInterface struct {
	*definition.Metadata
	Network     *Network
	SubNetwork  *SubNetwork
	HasPublicIP definition.BoolValue
	NATIP       definition.StringValue
}
