package sam

import (
	"github.com/aquasecurity/defsec/internal/types"
)

type SimpleTable struct {
	types.Metadata
	TableName        types.StringValue
	SSESpecification SSESpecification
}

type SSESpecification struct {
	types.Metadata

	Enabled        types.BoolValue
	KMSMasterKeyID types.StringValue
}
