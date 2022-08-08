package elasticsearch

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/elasticsearch"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) elasticsearch.Elasticsearch {
	return elasticsearch.Elasticsearch{
		Domains: getDomains(cfFile),
	}
}
