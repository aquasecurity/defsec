package sam

import (
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/provider/aws/iam"
)

type Function struct {
	types.Metadata
	FunctionName    types.StringValue
	Tracing         types.StringValue
	ManagedPolicies []types.StringValue
	Policies        []iam.Policy
}

const (
	TracingModePassThrough = "PassThrough"
	TracingModeActive      = "Active"
)

type Permission struct {
	types.Metadata
	Principal types.StringValue
	SourceARN types.StringValue
}
