package elb

import (
	"github.com/aquasecurity/defsec/provider/aws/elb"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result elb.ELB) {

	result.LoadBalancers = getLoadBalancers(cfFile)
	return result
}
