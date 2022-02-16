package ebs

import (
	"github.com/aquasecurity/defsec/provider/aws/ebs"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result ebs.EBS) {

	result.Volumes = getVolumes(cfFile)
	return result

}
