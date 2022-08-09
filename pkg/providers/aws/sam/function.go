package sam

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Function struct {
	defsecTypes.Metadata
	FunctionName    defsecTypes.StringValue
	Tracing         defsecTypes.StringValue
	ManagedPolicies []defsecTypes.StringValue
	Policies        []iam.Policy
}

const (
	TracingModePassThrough = "PassThrough"
	TracingModeActive      = "Active"
)

type Permission struct {
	defsecTypes.Metadata
	Principal defsecTypes.StringValue
	SourceARN defsecTypes.StringValue
}
