package compute

import "github.com/aquasecurity/defsec/definition"

type SubNetwork struct {
	*definition.Metadata
	Name           definition.StringValue
	EnableFlowLogs definition.BoolValue
}
