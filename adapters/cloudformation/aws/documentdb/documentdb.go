package documentdb

import (
	"github.com/aquasecurity/defsec/provider/aws/documentdb"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result documentdb.DocumentDB) {

	result.Clusters = getClusters(cfFile)
	return result

}
