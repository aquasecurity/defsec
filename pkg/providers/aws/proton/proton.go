package proton

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Proton struct {
	ListEnvironmentTemplates []EnvironmentTemplate
}

type EnvironmentTemplate struct {
	Metadata      defsecTypes.Metadata
	EncryptionKey defsecTypes.StringValue
}
