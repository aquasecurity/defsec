package github

import "github.com/aquasecurity/defsec/types"

type Action struct {
	types.Metadata
	EnvironmentSecrets []EnvironmentSecret
}

type EnvironmentSecret struct {
	Repository     types.StringValue
	Environment    types.StringValue
	SecretName     types.StringValue
	PlainTextValue types.StringValue
	EncryptedValue types.StringValue
}

func (a *Action) GetMetadata() *types.Metadata {
	return &a.Metadata
}

func (a *Action) GetRawValue() interface{} {
	return nil
}