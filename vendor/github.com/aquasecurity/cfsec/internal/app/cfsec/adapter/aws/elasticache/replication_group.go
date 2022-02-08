package elasticache

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/elasticache"
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
