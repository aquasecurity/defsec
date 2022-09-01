package bigquery

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type BigQuery struct {
	Datasets []Dataset
	Tables   []Table
}

type Dataset struct {
	defsecTypes.Metadata
	ID                             defsecTypes.StringValue
	AccessGrants                   []AccessGrant
	DefaultEncryptionConfiguration EncryptionConfiguration
}

type Table struct {
	defsecTypes.Metadata
	ID                      defsecTypes.StringValue
	EncryptionConfiguration EncryptionConfiguration
}

const (
	SpecialGroupAllAuthenticatedUsers = "allAuthenticatedUsers"
)

type AccessGrant struct {
	defsecTypes.Metadata
	Role         defsecTypes.StringValue
	Domain       defsecTypes.StringValue
	SpecialGroup defsecTypes.StringValue
}

type EncryptionConfiguration struct {
	defsecTypes.Metadata
	KMSKeyName defsecTypes.StringValue
}
