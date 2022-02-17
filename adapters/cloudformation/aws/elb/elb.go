package elb

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/provider/aws/elb"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result elb.ELB) {

	result.LoadBalancers = getLoadBalancers(cfFile)
	return result
}
