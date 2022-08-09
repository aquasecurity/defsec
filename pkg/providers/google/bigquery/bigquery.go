package bigquery

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type BigQuery struct {
	Datasets []Dataset
}

type Dataset struct {
	types2.Metadata
	ID           types2.StringValue
	AccessGrants []AccessGrant
}

const (
	SpecialGroupAllAuthenticatedUsers = "allAuthenticatedUsers"
)

type AccessGrant struct {
	types2.Metadata
	Role         types2.StringValue
	Domain       types2.StringValue
	SpecialGroup types2.StringValue
}
