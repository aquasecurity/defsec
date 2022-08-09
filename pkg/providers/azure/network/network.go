package network

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Network struct {
	SecurityGroups         []SecurityGroup
	NetworkWatcherFlowLogs []NetworkWatcherFlowLog
}

type SecurityGroup struct {
	defsecTypes.Metadata
	Rules []SecurityGroupRule
}

type SecurityGroupRule struct {
	defsecTypes.Metadata
	Outbound             defsecTypes.BoolValue
	Allow                defsecTypes.BoolValue
	SourceAddresses      []defsecTypes.StringValue
	SourcePorts          []PortRange
	DestinationAddresses []defsecTypes.StringValue
	DestinationPorts     []PortRange
	Protocol             defsecTypes.StringValue
}

type PortRange struct {
	defsecTypes.Metadata
	Start int
	End   int
}

func (r PortRange) Includes(port int) bool {
	return port >= r.Start && port <= r.End
}

type NetworkWatcherFlowLog struct {
	defsecTypes.Metadata
	RetentionPolicy RetentionPolicy
}

type RetentionPolicy struct {
	defsecTypes.Metadata
	Enabled defsecTypes.BoolValue
	Days    defsecTypes.IntValue
}
