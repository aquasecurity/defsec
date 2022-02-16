package neptune

import (
	"github.com/aquasecurity/defsec/provider/aws/neptune"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result neptune.Neptune) {

	result.Clusters = getClusters(cfFile)
	return result
}
