package elasticache

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/elasticache"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	"github.com/aquasecurity/defsec/pkg/types"
)

func getClusterGroups(ctx parser.FileContext) (clusters []elasticache.Cluster) {

	clusterResources := ctx.GetResourcesByType("AWS::ElastiCache::CacheCluster")

	for _, r := range clusterResources {
		cluster := elasticache.Cluster{
			Metadata:                 r.Metadata(),
			Id:                       types.StringDefault("", r.Metadata()),
			EngineVersion:            r.GetStringProperty("EngineVersion"),
			NumCacheNodes:            r.GetIntProperty("NumCacheNodes"),
			TransitEncryptionEnabled: r.GetBoolProperty("TransitEncryptionEnabled"),
			AtRestEncryptionEnabled:  types.Bool(false, r.Metadata()),
			CacheSubnetGroupName:     r.GetStringProperty("CacheSubnetGroupName"),
			ConfigurationEndpoint: elasticache.ConfigurationEndpoint{
				Metadata: r.Metadata(),
				Port:     r.GetIntProperty("ConfigurationEndpoint.Port"),
			},
			Engine:                 r.GetStringProperty("Engine"),
			NodeType:               r.GetStringProperty("CacheNodeType"),
			SnapshotRetentionLimit: r.GetIntProperty("SnapshotRetentionLimit"),
		}

		clusters = append(clusters, cluster)
	}

	return clusters
}
