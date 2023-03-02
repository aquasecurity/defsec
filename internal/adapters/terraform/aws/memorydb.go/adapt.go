package memorydb

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/memorydb"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) memorydb.MemoryDB {
	return memorydb.MemoryDB{
		Clusters: adaptClusters(modules),
	}
}

func adaptClusters(modules terraform.Modules) []memorydb.Cluster {
	var clusters []memorydb.Cluster
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_memorydb_cluster") {
			clusters = append(clusters, memorydb.Cluster{
				Metadata: resource.GetMetadata(),
				KmsKeyId: resource.GetAttribute("kms_key_arn").AsStringValueOrDefault("", resource),
			})
		}
	}
	return clusters
}
