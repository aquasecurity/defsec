package computing

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Instance struct {
	Metadata          defsecTypes.Metadata
	SecurityGroup     defsecTypes.StringValue
	NetworkInterfaces []NetworkInterface
}

type NetworkInterface struct {
	Metadata  defsecTypes.Metadata
	NetworkID defsecTypes.StringValue
}
