package comprehend

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/comprehend"
	"github.com/aquasecurity/defsec/pkg/terraform"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

func Adapt(modules terraform.Modules) comprehend.Comprehend {
	return comprehend.Comprehend{
		DocumentClassificationJobs: getDCJobs(modules),
	}
}

func getDCJobs(modules terraform.Modules) []comprehend.DocumentClassificationJob {
	var jobs []comprehend.DocumentClassificationJob
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_comprehend_document_classifier") {
			var key defsecTypes.StringValue
			if configblock := resource.GetBlock("output_data_config"); configblock.IsNotNil() {
				key = configblock.GetAttribute("kms_key_id").AsStringValueOrDefault("", configblock)
			}
			jobs = append(jobs, comprehend.DocumentClassificationJob{
				Metadata:       resource.GetMetadata(),
				VolumeKmsKeyId: resource.GetAttribute("volume_kms_key_id").AsStringValueOrDefault("", resource),
				KmsKeyId:       key,
			})
		}
	}
	return jobs
}
