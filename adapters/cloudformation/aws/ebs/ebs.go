package ebs

import (
	"github.com/aquasecurity/defsec/provider/aws/ebs"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result ebs.EBS) {
	defer func() {
		if r := recover(); r != nil {
			// metadata := cfFile.Metadata()
			// debug.Log("There were errors adapting %s from %s", reflect.TypeOf(result), metadata.Range().GetFilename())
		}
	}()

	result.Volumes = getVolumes(cfFile)
	return result

}
