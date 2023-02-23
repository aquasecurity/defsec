package emr

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/emr"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func Adapt(cfFile parser.FileContext) emr.EMR {
	return emr.EMR{
		Clusters:              getClusters(cfFile),
		SecurityConfiguration: getSecurityConfigurations(cfFile),
	}
}
