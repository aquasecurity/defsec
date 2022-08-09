package compute

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type SubNetwork struct {
	types2.Metadata
	Name           types2.StringValue
	EnableFlowLogs types2.BoolValue
}
