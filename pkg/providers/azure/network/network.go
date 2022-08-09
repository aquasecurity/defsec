package network

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type Network struct {
	SecurityGroups         []SecurityGroup
	NetworkWatcherFlowLogs []NetworkWatcherFlowLog
}

type SecurityGroup struct {
	types2.Metadata
	Rules []SecurityGroupRule
}

type SecurityGroupRule struct {
	types2.Metadata
	Outbound             types2.BoolValue
	Allow                types2.BoolValue
	SourceAddresses      []types2.StringValue
	SourcePorts          []PortRange
	DestinationAddresses []types2.StringValue
	DestinationPorts     []PortRange
	Protocol             types2.StringValue
}

type PortRange struct {
	types2.Metadata
	Start int
	End   int
}

func (r PortRange) Includes(port int) bool {
	return port >= r.Start && port <= r.End
}

type NetworkWatcherFlowLog struct {
	types2.Metadata
	RetentionPolicy RetentionPolicy
}

type RetentionPolicy struct {
	types2.Metadata
	Enabled types2.BoolValue
	Days    types2.IntValue
}
