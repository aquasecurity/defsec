package codepipeline

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/codepipeline"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) codepipeline.Codepipeline {
	return codepipeline.Codepipeline{
		Pipelines: getPipeline(cfFile),
	}
}
