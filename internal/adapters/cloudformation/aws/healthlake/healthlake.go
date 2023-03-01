package healthlake

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/healthlake"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func Adapt(cfFile parser.FileContext) healthlake.HealthLake {
	return healthlake.HealthLake{
		FHIRDatastores: getDatastores(cfFile),
	}
}
