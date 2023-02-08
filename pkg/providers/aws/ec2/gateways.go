package ec2

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type InternetGateway struct {
	Metadata    defsecTypes.Metadata
	Id          defsecTypes.StringValue
	Attachments []GatewayAttachment
}

type GatewayAttachment struct {
	Metadata defsecTypes.Metadata
	VpcId    defsecTypes.StringValue
	State    defsecTypes.StringValue
}

type NatGateway struct {
	Metadata defsecTypes.Metadata
	Id       defsecTypes.StringValue
	VpcId    defsecTypes.StringValue
	SubnetId defsecTypes.StringValue
}

type VpnGateway struct {
	Metadata   defsecTypes.Metadata
	Attachment []GatewayAttachment
}

type VpnConnection struct {
	Metadata           defsecTypes.Metadata
	ID                 defsecTypes.StringValue
	VgwTelemetryStatus []defsecTypes.StringValue
}

type EgressOnlyInternetGateway struct {
	Metadata defsecTypes.Metadata
	Id       defsecTypes.StringValue
}
