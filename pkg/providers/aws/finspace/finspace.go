package finspace

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type ListEnvironements struct {
	Environments []Environment
}

type Environment struct {
	Metadata       defsecTypes.Metadata
	EnvironmentArn defsecTypes.StringValue
	KmsKeyId       defsecTypes.StringValue
}
