package codepipeline

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/codepipeline"
	"github.com/aquasecurity/defsec/pkg/terraform"
	"github.com/aquasecurity/defsec/pkg/types"
)

func Adapt(modules terraform.Modules) codepipeline.Codepipeline {
	return codepipeline.Codepipeline{
		Pipelines: adaptPipeline(modules),
	}
}

func adaptPipeline(modules terraform.Modules) []codepipeline.Pipeline {
	var pipelines []codepipeline.Pipeline
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_codepipeline") {

			var key types.StringValue
			if storeBlock := resource.GetBlock("artifact_store"); storeBlock.IsNotNil() {
				if keyBlock := storeBlock.GetBlock("encryption_key"); keyBlock.IsNotNil() {
					key = keyBlock.GetAttribute("id").AsStringValueOrDefault("", keyBlock)
				}
			}

			pipelines = append(pipelines, codepipeline.Pipeline{
				Metadata:      resource.GetMetadata(),
				EncryptionKey: key,
			})
		}
	}
	return pipelines
}
