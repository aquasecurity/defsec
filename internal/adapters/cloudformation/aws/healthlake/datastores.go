package healthlake

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/healthlake"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func getDatastores(ctx parser.FileContext) []healthlake.FHIRDatastore {
	var datastores []healthlake.FHIRDatastore

	for _, r := range ctx.GetResourcesByType("AWS::HealthLake::FHIRDatastore") {
		datastores = append(datastores, healthlake.FHIRDatastore{
			Metadata: r.Metadata(),
			KmsKeyId: r.GetStringProperty("SseConfiguration.KmsEncryptionConfig.KmsKeyId"),
		})
	}
	return datastores
}
