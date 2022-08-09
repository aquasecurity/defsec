package sam

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type SimpleTable struct {
	types2.Metadata
	TableName        types2.StringValue
	SSESpecification SSESpecification
}

type SSESpecification struct {
	types2.Metadata

	Enabled        types2.BoolValue
	KMSMasterKeyID types2.StringValue
}
