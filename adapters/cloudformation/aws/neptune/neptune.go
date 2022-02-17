package neptune

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/provider/aws/neptune"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result neptune.Neptune) {

	result.Clusters = getClusters(cfFile)
	return result
}
