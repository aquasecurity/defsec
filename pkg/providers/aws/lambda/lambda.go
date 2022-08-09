package lambda

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type Lambda struct {
	Functions []Function
}

type Function struct {
	types2.Metadata
	Tracing     Tracing
	Permissions []Permission
}

const (
	TracingModePassThrough = "PassThrough"
	TracingModeActive      = "Active"
)

type Tracing struct {
	types2.Metadata
	Mode types2.StringValue
}

type Permission struct {
	types2.Metadata
	Principal types2.StringValue
	SourceARN types2.StringValue
}
