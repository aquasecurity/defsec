package msk

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/provider/aws/msk"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result msk.MSK) {

	result.Clusters = getClusters(cfFile)
	return result

}
