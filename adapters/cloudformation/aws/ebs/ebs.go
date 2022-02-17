package ebs

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/provider/aws/ebs"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result ebs.EBS) {

	result.Volumes = getVolumes(cfFile)
	return result

}
