package rds

import (
	"reflect"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/debug"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/rds"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result rds.RDS) {
	defer func() {
		if r := recover(); r != nil {
			metadata := cfFile.Metadata()
			debug.Log("There were errors adapting %s from %s", reflect.TypeOf(result), metadata.Range().GetFilename())
		}
	}()

	clusters, orphans := getClustersAndInstances(cfFile)

	result.Instances = orphans
	result.Clusters = clusters
	result.Classic = getClassic(cfFile)
	return result
}
