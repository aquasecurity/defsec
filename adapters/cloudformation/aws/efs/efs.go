package efs

import (
	"github.com/aquasecurity/defsec/provider/aws/efs"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result efs.EFS) {

	result.FileSystems = getFileSystems(cfFile)
	return result
}
