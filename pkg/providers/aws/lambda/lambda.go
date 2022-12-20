package lambda

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Lambda struct {
	Functions []Function
}

type Function struct {
	Metadata    defsecTypes.Metadata
	Tracing     Tracing
	VpcConfig   VpcConfig
	Permissions []Permission
}

const (
	TracingModePassThrough = "PassThrough"
	TracingModeActive      = "Active"
)

type Tracing struct {
	Metadata defsecTypes.Metadata
	Mode     defsecTypes.StringValue
}

type VpcConfig struct {
	Metadata defsecTypes.Metadata
	VpcId    defsecTypes.StringValue
}

type Permission struct {
	Metadata  defsecTypes.Metadata
	Principal defsecTypes.StringValue
	SourceARN defsecTypes.StringValue
}
