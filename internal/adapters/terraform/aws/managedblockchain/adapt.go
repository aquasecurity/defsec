package managedblockchain

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/managedblockchain"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) managedblockchain.ManagedBlockchain {
	return managedblockchain.ManagedBlockchain{
		Members: nil,
	}
}
