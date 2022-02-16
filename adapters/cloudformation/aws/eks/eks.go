package eks

import (
	"github.com/aquasecurity/defsec/provider/aws/eks"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result eks.EKS) {

	result.Clusters = getClusters(cfFile)
	return result
}
