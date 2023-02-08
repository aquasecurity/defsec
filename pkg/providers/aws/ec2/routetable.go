package ec2

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type RouteTable struct {
	Metadata     defsecTypes.Metadata
	RouteTableId defsecTypes.StringValue
	Routes       []Route
	Associations []Association
}

type Association struct {
	Metadata defsecTypes.Metadata
	SubnetId defsecTypes.StringValue
}

type Route struct {
	Metadata               defsecTypes.Metadata
	GatewayId              defsecTypes.StringValue
	DestinationCidrBlock   defsecTypes.StringValue
	VpcPeeringConnectionId defsecTypes.StringValue
}

type Address struct {
	Metadata      defsecTypes.Metadata
	Domain        defsecTypes.StringValue
	AllocationId  defsecTypes.StringValue
	AssociationId defsecTypes.StringValue
}
