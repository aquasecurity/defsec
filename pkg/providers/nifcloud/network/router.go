package network

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Router struct {
	Metadata          defsecTypes.Metadata
	SecurityGroup     defsecTypes.StringValue
	NetworkInterfaces []NetworkInterface
}
