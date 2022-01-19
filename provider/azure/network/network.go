package network

import "github.com/aquasecurity/defsec/types"

type Network struct {
	types.Metadata
	SecurityGroups         []SecurityGroup
	NetworkWatcherFlowLogs []NetworkWatcherFlowLog
}

type SecurityGroup struct {
	types.Metadata
	InboundAllowRules  []SecurityGroupRule
	InboundDenyRules   []SecurityGroupRule
	OutboundAllowRules []SecurityGroupRule
	OutboundDenyRules  []SecurityGroupRule
}

type SecurityGroupRule struct {
	types.Metadata
	SourceAddresses       []types.StringValue
	SourcePortRanges      []types.StringValue
	DestinationAddresses  []types.StringValue
	DestinationPortRanges []types.StringValue
}

type NetworkWatcherFlowLog struct {
	types.Metadata
	RetentionPolicy RetentionPolicy
}

type RetentionPolicy struct {
	types.Metadata
	Enabled types.BoolValue
	Days    types.IntValue
}
