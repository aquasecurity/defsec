package elastictranscoder

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/elastictranscoder"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) elastictranscoder.ElasticTranscoder {
	return elastictranscoder.ElasticTranscoder{
		Pipelines: adaptPipelines(modules),
	}
}

func adaptPipelines(modules terraform.Modules) []elastictranscoder.Pipeline {
	var pipelines []elastictranscoder.Pipeline
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_elastictranscoder_pipeline") {
			pipelines = append(pipelines, adaptPipeline(resource))
		}
	}
	return pipelines
}

func adaptPipeline(resource *terraform.Block) elastictranscoder.Pipeline {

	return elastictranscoder.Pipeline{
		Metadata:     resource.GetMetadata(),
		AwsKmsKeyArn: resource.GetAttribute("aws_kms_key_arn").AsStringValueOrDefault("", resource),
		Outputs:      nil,
	}
}
