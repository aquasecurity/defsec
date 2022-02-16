package elasticsearch

import (
	"github.com/aquasecurity/defsec/provider/aws/elasticsearch"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result elasticsearch.Elasticsearch) {
	defer func() {
		if r := recover(); r != nil {
			// metadata := cfFile.Metadata()
			// debug.Log("There were errors adapting %s from %s", reflect.TypeOf(result), metadata.Range().GetFilename())
		}
	}()

	result.Domains = getDomains(cfFile)
	return result
}
