package elb

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type ELB struct {
	LoadBalancersV1      []LoadBalancerV1
	LoadBalancers        []LoadBalancer
	TargetGroups         []TargetGroup
	LoadBalancerPolicies []LoadBalancerPolicy
}

const (
	TypeApplication = "application"
	TypeGateway     = "gateway"
	TypeNetwork     = "network"
	TypeClassic     = "classic"
)

type LoadBalancer struct {
	Metadata                defsecTypes.Metadata
	Type                    defsecTypes.StringValue
	DropInvalidHeaderFields defsecTypes.BoolValue
	Internal                defsecTypes.BoolValue
	Listeners               []Listener
	Attibute                []AttibuteV2
}

type TargetGroup struct {
	Metadata     defsecTypes.Metadata
	Attribute    []AttibuteV2
	TargetHealth []TargetHealth
}

type TargetHealth struct {
	Metadata          defsecTypes.Metadata
	TargetId          defsecTypes.StringValue
	TargetHealthState defsecTypes.StringValue
}

type AttibuteV2 struct {
	Metadata defsecTypes.Metadata
	Key      defsecTypes.StringValue
	Value    defsecTypes.StringValue
}

type Listener struct {
	Metadata       defsecTypes.Metadata
	Protocol       defsecTypes.StringValue
	Certificates   []Certificate
	TLSPolicy      defsecTypes.StringValue
	DefaultActions []Action
}

type Action struct {
	Metadata defsecTypes.Metadata
	Type     defsecTypes.StringValue
}

type Certificate struct {
	Metadata defsecTypes.Metadata
	Arn      defsecTypes.StringValue
}
