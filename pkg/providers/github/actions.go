package github

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Action struct {
	defsecTypes.Metadata
	EnvironmentSecrets []EnvironmentSecret
}

type EnvironmentSecret struct {
	defsecTypes.Metadata
	Repository     defsecTypes.StringValue
	Environment    defsecTypes.StringValue
	SecretName     defsecTypes.StringValue
	PlainTextValue defsecTypes.StringValue
	EncryptedValue defsecTypes.StringValue
}
