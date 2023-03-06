package transfer

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/transfer"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) transfer.Transfer {
	return transfer.Transfer{
		ListServers: getListServers(cfFile),
	}
}
