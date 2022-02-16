package ec2

import (
	"github.com/aquasecurity/defsec/provider/aws/ec2"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result ec2.EC2) {
	defer func() {
		if r := recover(); r != nil {
			// metadata := cfFile.Metadata()
			// debug.Log("There were errors adapting %s from %s", reflect.TypeOf(result), metadata.Range().GetFilename())
		}
	}()

	result.Instances = getInstances(cfFile)
	return result
}
