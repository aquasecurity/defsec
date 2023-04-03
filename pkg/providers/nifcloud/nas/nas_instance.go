package nas

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type NASInstance struct {
	Metadata  defsecTypes.Metadata
	NetworkID defsecTypes.StringValue
}
