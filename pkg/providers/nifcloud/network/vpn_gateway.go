package network

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type VpnGateway struct {
	Metadata      defsecTypes.Metadata
	SecurityGroup defsecTypes.StringValue
}
