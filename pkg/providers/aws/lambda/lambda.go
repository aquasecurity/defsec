package lambda

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Lambda struct {
	Functions []Function
}

type Function struct {
	defsecTypes.Metadata
	Tracing     Tracing
	Permissions []Permission
}

const (
	TracingModePassThrough = "PassThrough"
	TracingModeActive      = "Active"
)

type Tracing struct {
	defsecTypes.Metadata
	Mode defsecTypes.StringValue
}

type Permission struct {
	defsecTypes.Metadata
	Principal defsecTypes.StringValue
	SourceARN defsecTypes.StringValue
}
