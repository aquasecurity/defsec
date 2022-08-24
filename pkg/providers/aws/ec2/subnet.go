package ec2

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Subnet struct {
	defsecTypes.Metadata
	MapPublicIpOnLaunch defsecTypes.BoolValue
}
