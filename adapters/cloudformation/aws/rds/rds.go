package rds

import (
	"github.com/aquasecurity/defsec/provider/aws/rds"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result rds.RDS) {
	defer func() {
		if r := recover(); r != nil {
			// metadata := cfFile.Metadata()
			// debug.Log("There were errors adapting %s from %s", reflect.TypeOf(result), metadata.Range().GetFilename())
		}
	}()

	clusters, orphans := getClustersAndInstances(cfFile)

	result.Instances = orphans
	result.Clusters = clusters
	result.Classic = getClassic(cfFile)
	return result
}
