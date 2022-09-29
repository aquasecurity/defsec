package compute

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type SubNetwork struct {
	Metadata       defsecTypes.Metadata
	Name           defsecTypes.StringValue
	EnableFlowLogs defsecTypes.BoolValue
}
