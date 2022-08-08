package codebuild

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/codebuild"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) codebuild.CodeBuild {
	return codebuild.CodeBuild{
		Projects: getProjects(cfFile),
	}
}
