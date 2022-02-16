package ecs

import (
	"github.com/aquasecurity/defsec/provider/aws/ecs"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result ecs.ECS) {
	defer func() {
		if r := recover(); r != nil {
			// metadata := cfFile.Metadata()
			// debug.Log("There were errors adapting %s from %s", reflect.TypeOf(result), metadata.Range().GetFilename())
		}
	}()

	result.Clusters = getClusters(cfFile)
	result.TaskDefinitions = getTaskDefinitions(cfFile)
	return result

}
