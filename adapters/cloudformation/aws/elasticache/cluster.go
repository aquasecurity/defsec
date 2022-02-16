package elasticache

import (
	"github.com/aquasecurity/defsec/provider/aws/elasticache"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

func getClusterGroups(ctx parser.FileContext) (clusters []elasticache.Cluster) {

	clusterResources := ctx.GetResourceByType("AWS::ElastiCache::CacheCluster")

	for _, r := range clusterResources {
		cluster := elasticache.Cluster{
			Metadata:               r.Metadata(),
			Engine:                 r.GetStringProperty("Engine"),
			NodeType:               r.GetStringProperty("CacheNodeType"),
			SnapshotRetentionLimit: r.GetIntProperty("SnapshotRetentionLimit"),
		}

		clusters = append(clusters, cluster)
	}

	return clusters
}
