package transfer

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/transfer"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func getListServers(ctx parser.FileContext) (transferServerInfo []transfer.Servers) {

	serverResources := ctx.GetResourcesByType("AWS::Transfer::Server")

	for _, r := range serverResources {
		serverInfo := transfer.Servers{
			Metadata:  r.Metadata(),
			ServerArn: r.GetStringProperty("Arn"),
		}

		transferServerInfo = append(transferServerInfo, serverInfo)
	}

	return transferServerInfo
}
