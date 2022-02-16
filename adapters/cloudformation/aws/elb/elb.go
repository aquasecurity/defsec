package elb

import (
	"github.com/aquasecurity/defsec/provider/aws/elb"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result elb.ELB) {
	defer func() {
		if r := recover(); r != nil {
			// metadata := cfFile.Metadata()
			// debug.Log("There were errors adapting %s from %s", reflect.TypeOf(result), metadata.Range().GetFilename())
		}
	}()

	result.LoadBalancers = getLoadBalancers(cfFile)
	return result
}
