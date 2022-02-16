package elasticache

import (
	"github.com/aquasecurity/defsec/provider/aws/elasticache"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

func getReplicationGroups(ctx parser.FileContext) (replicationGroups []elasticache.ReplicationGroup) {

	replicationGroupResources := ctx.GetResourceByType("AWS::ElastiCache::ReplicationGroup")

	for _, r := range replicationGroupResources {
		replicationGroup := elasticache.ReplicationGroup{
			Metadata:                 r.Metadata(),
			TransitEncryptionEnabled: r.GetBoolProperty("TransitEncryptionEnabled"),
		}

		replicationGroups = append(replicationGroups, replicationGroup)
	}

	return replicationGroups
}
