package managedblockchain

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/managedblockchain"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	"github.com/aquasecurity/defsec/pkg/types"
)

func getMembers(ctx parser.FileContext) []managedblockchain.Member {
	var MB []managedblockchain.Member

	for _, r := range ctx.GetResourcesByType("AWS::ManagedBlockchain::Member") {
		MB = append(MB, managedblockchain.Member{
			Metadata:  r.Metadata(),
			KmsKeyArn: types.String("", r.Metadata()),
		})
	}
	return MB
}
