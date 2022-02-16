package elasticache

import (
	"github.com/aquasecurity/defsec/provider/aws/elasticache"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result elasticache.ElastiCache) {
	defer func() {
		if r := recover(); r != nil {
			// metadata := cfFile.Metadata()
			// debug.Log("There were errors adapting %s from %s", reflect.TypeOf(result), metadata.Range().GetFilename())
		}
	}()

	result.Clusters = getClusterGroups(cfFile)
	result.ReplicationGroups = getReplicationGroups(cfFile)
	result.SecurityGroups = getSecurityGroups(cfFile)
	return result
}
