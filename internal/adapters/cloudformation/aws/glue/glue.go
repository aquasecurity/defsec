package glue

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/glue"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func Adapt(cfFile parser.FileContext) glue.Glue {
	return glue.Glue{
		DataCatalogEncryptionSettings: getDataCatalogEncryptionSettings(cfFile),
		SecurityConfigurations:        getSecurityConfigurations(cfFile),
	}
}
