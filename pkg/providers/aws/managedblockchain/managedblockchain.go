package managedblockchain

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type ManagedBlockchain struct {
	Members []Member
}

type Member struct {
	Metadata  defsecTypes.Metadata
	KmsKeyArn defsecTypes.StringValue
}
