package msk

import (
	"github.com/aquasecurity/defsec/provider/aws/msk"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result msk.MSK) {

	result.Clusters = getClusters(cfFile)
	return result

}
