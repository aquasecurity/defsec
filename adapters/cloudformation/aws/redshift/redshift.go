package redshift

import (
	"github.com/aquasecurity/defsec/provider/aws/redshift"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result redshift.Redshift) {

	result.Clusters = getClusters(cfFile)
	result.SecurityGroups = getSecurityGroups(cfFile)
	return result

}
