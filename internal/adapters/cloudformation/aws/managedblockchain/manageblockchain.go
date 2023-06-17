package managedblockchain

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/managedblockchain"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func Adapt(cfFile parser.FileContext) managedblockchain.ManagedBlockchain {
	return managedblockchain.ManagedBlockchain{
		Members: getMembers(cfFile),
	}
}
