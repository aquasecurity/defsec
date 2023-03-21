package devopsguru

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/devopsguru"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func getChannel(ctx parser.FileContext) []devopsguru.NotificationChannel {

	resources := ctx.GetResourcesByType("AWS::DevOpsGuru::NotificationChannel")

	var NCs []devopsguru.NotificationChannel
	for _, r := range resources {
		NCs = append(NCs, devopsguru.NotificationChannel{
			Metadata: r.Metadata(),
		})
	}
	return NCs
}
