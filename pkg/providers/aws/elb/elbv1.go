package elb

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type LoadBalancerV1 struct {
	Metadata   defsecTypes.Metadata
	Name       defsecTypes.StringValue
	DNSName    defsecTypes.StringValue
	Listener   []ListenerV1
	Instances  []Instance
	Attributes Attibute
}

type LoadBalancerPolicy struct {
	Metadata                    defsecTypes.Metadata
	PolicyAttributeDescriptions []PolicyAttributeDescription
}

type PolicyAttributeDescription struct {
	Metadata defsecTypes.Metadata
	Name     defsecTypes.StringValue
	Value    defsecTypes.StringValue
}

type ListenerV1 struct {
	Metadata defsecTypes.Metadata
	Protocol defsecTypes.StringValue
}

type Instance struct {
	Metadata defsecTypes.Metadata
	Id       defsecTypes.StringValue
}

type Attibute struct {
	Metadata                      defsecTypes.Metadata
	AccessLogEnabled              defsecTypes.BoolValue
	CrossZoneLoadBalancingEnabled defsecTypes.BoolValue
	ConnectionDrainingEnabled     defsecTypes.BoolValue
}
