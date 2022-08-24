package sam

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type SimpleTable struct {
	defsecTypes.Metadata
	TableName        defsecTypes.StringValue
	SSESpecification SSESpecification
}

type SSESpecification struct {
	defsecTypes.Metadata

	Enabled        defsecTypes.BoolValue
	KMSMasterKeyID defsecTypes.StringValue
}
