package config

import (
	"github.com/aquasecurity/defsec/provider/aws/config"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result config.Config) {

	defer func() {
		if r := recover(); r != nil {
			// metadata := cfFile.Metadata()
			// debug.Log("There were errors adapting %s from %s", reflect.TypeOf(result), metadata.Range().GetFilename())
		}
	}()

	result.ConfigurationAggregrator = getConfiguraionAggregator(cfFile)
	return result

}
