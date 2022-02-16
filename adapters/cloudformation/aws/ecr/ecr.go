package ecr

import (
	"github.com/aquasecurity/defsec/provider/aws/ecr"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result ecr.ECR) {

	result.Repositories = getRepositories(cfFile)
	return result

}
