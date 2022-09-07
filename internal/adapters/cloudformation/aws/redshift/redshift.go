package redshift

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/redshift"
	"github.com/aquasecurity/defsec/pkg/scanners/aws/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) redshift.Redshift {
	return redshift.Redshift{
		Clusters:       getClusters(cfFile),
		SecurityGroups: getSecurityGroups(cfFile),
	}
}
