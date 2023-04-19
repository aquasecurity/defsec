package lambda

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Lambda struct {
	Functions []Function
}

type Function struct {
	Metadata     defsecTypes.Metadata
	Tracing      Tracing
	Permissions  []Permission
	FunctionName defsecTypes.StringValue
	FunctionArn  defsecTypes.StringValue
	VpcConfig    VpcConfig
	Runtime      defsecTypes.StringValue
	Envrionment  Environment
}

type Environment struct {
	Metadata  defsecTypes.Metadata
	Variables defsecTypes.MapValue
}

type VpcConfig struct {
	Metadata defsecTypes.Metadata
	VpcId    defsecTypes.StringValue
}

const (
	TracingModePassThrough = "PassThrough"
	TracingModeActive      = "Active"
)

type Tracing struct {
	Metadata defsecTypes.Metadata
	Mode     defsecTypes.StringValue
}

type Permission struct {
	Metadata  defsecTypes.Metadata
	Principal defsecTypes.StringValue
	SourceARN defsecTypes.StringValue
}
