package codepipeline

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/codepipeline"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func getPipeline(ctx parser.FileContext) []codepipeline.Pipeline {

	var pipelines []codepipeline.Pipeline

	resources := ctx.GetResourcesByType("AWS::CodePipeline::Pipeline")

	for _, r := range resources {
		pipelines = append(pipelines, codepipeline.Pipeline{
			Metadata:      r.Metadata(),
			EncryptionKey: r.GetStringProperty("ArtifactStore.EncryptionKey.Id"),
		})
	}

	return pipelines
}
