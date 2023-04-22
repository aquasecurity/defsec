package transfer

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/transfer"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) transfer.Transfer {
	return transfer.Transfer{
		ListServers: adaptListServers(modules),
	}
}

func adaptListServers(modules terraform.Modules) []transfer.Servers {
	var listServerInfo []transfer.Servers
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_transfer_server") {
			listServerInfo = append(listServerInfo, adaptListServer(resource))
		}
	}
	return listServerInfo
}

func adaptListServer(resource *terraform.Block) transfer.Servers {

	serverinfo := transfer.Servers{
		Metadata:  resource.GetMetadata(),
		ServerArn: resource.GetAttribute("arn").AsStringValueOrDefault("", resource),
	}

	return serverinfo
}
