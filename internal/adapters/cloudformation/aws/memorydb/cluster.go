package memorydb

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/memorydb"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func getClusters(ctx parser.FileContext) []memorydb.Cluster {

	var clusters []memorydb.Cluster

	for _, r := range ctx.GetResourcesByType("AWS::MemoryDB::Cluster") {
		clusters = append(clusters, memorydb.Cluster{
			Metadata: r.Metadata(),
			KmsKeyId: r.GetStringProperty("KmsKeyId"),
		})
	}
	return clusters
}
