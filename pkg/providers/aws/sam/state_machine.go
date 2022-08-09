package sam

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type StateMachine struct {
	types2.Metadata
	Name                 types2.StringValue
	LoggingConfiguration LoggingConfiguration
	ManagedPolicies      []types2.StringValue
	Policies             []iam.Policy
	Tracing              TracingConfiguration
}

type LoggingConfiguration struct {
	types2.Metadata
	LoggingEnabled types2.BoolValue
}

type TracingConfiguration struct {
	types2.Metadata
	Enabled types2.BoolValue
}
