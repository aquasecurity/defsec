package ec2

import (
	"github.com/aquasecurity/defsec/provider/aws/ec2"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result ec2.EC2) {

	result.Instances = getInstances(cfFile)
	return result
}
