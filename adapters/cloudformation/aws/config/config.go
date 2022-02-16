package config

import (
	"github.com/aquasecurity/defsec/provider/aws/config"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result config.Config) {

	result.ConfigurationAggregrator = getConfiguraionAggregator(cfFile)
	return result

}
