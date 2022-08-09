package github

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type Action struct {
	types2.Metadata
	EnvironmentSecrets []EnvironmentSecret
}

type EnvironmentSecret struct {
	types2.Metadata
	Repository     types2.StringValue
	Environment    types2.StringValue
	SecretName     types2.StringValue
	PlainTextValue types2.StringValue
	EncryptedValue types2.StringValue
}
