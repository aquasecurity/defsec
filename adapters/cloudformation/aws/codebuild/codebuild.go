package codebuild

import (
	"github.com/aquasecurity/defsec/provider/aws/codebuild"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result codebuild.CodeBuild) {

	result.Projects = getProjects(cfFile)
	return result

}
