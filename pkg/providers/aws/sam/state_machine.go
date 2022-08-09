package sam

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type StateMachine struct {
	defsecTypes.Metadata
	Name                 defsecTypes.StringValue
	LoggingConfiguration LoggingConfiguration
	ManagedPolicies      []defsecTypes.StringValue
	Policies             []iam.Policy
	Tracing              TracingConfiguration
}

type LoggingConfiguration struct {
	defsecTypes.Metadata
	LoggingEnabled defsecTypes.BoolValue
}

type TracingConfiguration struct {
	defsecTypes.Metadata
	Enabled defsecTypes.BoolValue
}
