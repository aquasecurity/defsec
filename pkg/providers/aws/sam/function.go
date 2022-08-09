package sam

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type Function struct {
	types2.Metadata
	FunctionName    types2.StringValue
	Tracing         types2.StringValue
	ManagedPolicies []types2.StringValue
	Policies        []iam.Policy
}

const (
	TracingModePassThrough = "PassThrough"
	TracingModeActive      = "Active"
)

type Permission struct {
	types2.Metadata
	Principal types2.StringValue
	SourceARN types2.StringValue
}
