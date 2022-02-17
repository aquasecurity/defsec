package elasticsearch

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/provider/aws/elasticsearch"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result elasticsearch.Elasticsearch) {

	result.Domains = getDomains(cfFile)
	return result
}
