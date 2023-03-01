package glue

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/glue"
	"github.com/aquasecurity/defsec/pkg/terraform"
	"github.com/aquasecurity/defsec/pkg/types"
)

func Adapt(modules terraform.Modules) glue.Glue {
	return glue.Glue{
		SecurityConfigurations:        adaptSecurityConfigurations(modules),
		DataCatalogEncryptionSettings: adaptEncryptionSettings(modules),
	}
}

func adaptSecurityConfigurations(modules terraform.Modules) []glue.SecurityConfiguration {
	var securityconfigurations []glue.SecurityConfiguration
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_glue_security_configuration") {
			securityconfigurations = append(securityconfigurations, adaptSecurityConfiguration(resource))
		}
	}
	return securityconfigurations
}

func adaptSecurityConfiguration(resource *terraform.Block) glue.SecurityConfiguration {

	var cloudwatchencrypt, jobmarkencrypt types.StringValue
	var s3encrypt []glue.S3Encryption
	if encrypBlock := resource.GetBlock("encryption_configuration "); encrypBlock.IsNotNil() {
		if cloudwatchBlock := encrypBlock.GetBlock("cloudwatch_encryption"); cloudwatchBlock.IsNotNil() {
			cloudwatchencrypt = cloudwatchBlock.GetAttribute("cloudwatch_encryption_mode").AsStringValueOrDefault("", cloudwatchBlock)
		}

		if jobmarkBlock := encrypBlock.GetBlock("job_bookmarks_encryption"); jobmarkBlock.IsNotNil() {
			jobmarkencrypt = jobmarkBlock.GetAttribute("job_bookmarks_encryption_mode").AsStringValueOrDefault("", jobmarkBlock)
		}

		for _, e := range encrypBlock.GetBlocks("s3_encryption") {
			s3encrypt = append(s3encrypt, glue.S3Encryption{
				Metadata:         e.GetMetadata(),
				S3EncryptionMode: e.GetAttribute("s3_encryption_mode").AsStringValueOrDefault("", e),
			})
		}

	}

	return glue.SecurityConfiguration{
		Metadata: resource.GetMetadata(),
		EncryptionConfiguration: glue.EncryptionConfiguration{
			Metadata:                   resource.GetMetadata(),
			CloudWatchEncryptionMode:   cloudwatchencrypt,
			JobBookmarksEncryptionMode: jobmarkencrypt,
			S3Encryptions:              s3encrypt,
		},
	}
}

func adaptEncryptionSettings(modules terraform.Modules) glue.DataCatalogEncryptionSetting {
	var settings glue.DataCatalogEncryptionSetting
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_glue_data_catalog_encryption_settings") {

			var encrypmode, kmskeyid types.StringValue
			if encryBlock := resource.GetBlock("encryption_at_rest"); encryBlock.IsNotNil() {
				encrypmode = encryBlock.GetAttribute("catalog_encryption_mode").AsStringValueOrDefault("", encryBlock)
				kmskeyid = encryBlock.GetAttribute("sse_aws_kms_key_id").AsStringValueOrDefault("", encryBlock)

			}
			settings = glue.DataCatalogEncryptionSetting{
				Metadata: resource.GetMetadata(),
				EncryptionAtRest: glue.EncryptionAtRest{
					CatalogEncryptionMode: encrypmode,
					SseAwsKmsKeyId:        kmskeyid,
				},
			}
		}
	}
	return settings
}
