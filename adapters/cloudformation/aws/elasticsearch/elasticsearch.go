package elasticsearch

import (
	"github.com/aquasecurity/defsec/provider/aws/elasticsearch"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result elasticsearch.Elasticsearch) {

	result.Domains = getDomains(cfFile)
	return result
}
