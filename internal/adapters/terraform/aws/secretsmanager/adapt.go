package secretsmanager

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/secretsmanager"
	"github.com/aquasecurity/defsec/pkg/terraform"
	"github.com/aquasecurity/defsec/pkg/types"
)

func Adapt(modules terraform.Modules) secretsmanager.SecretsManager {
	return secretsmanager.SecretsManager{
		Secrets: adaptSecrets(modules),
	}
}

func adaptSecrets(modules terraform.Modules) []secretsmanager.Secret {
	var secrets []secretsmanager.Secret
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_secretsmanager_secret") {
			secrets = append(secrets, secretsmanager.Secret{
				Metadata:               resource.GetMetadata(),
				Arn:                    resource.GetAttribute("Arn").AsStringValueOrDefault("", resource),
				KmsKeyId:               resource.GetAttribute("kms_key_id").AsStringValueOrDefault("", resource),
				RotationEnabled:        resource.GetAttribute("rotation_enabled").AsBoolValueOrDefault(false, resource),
				AutomaticallyAfterDays: getRotation(resource, modules),
				Tags:                   gettags(resource),
			})
		}
	}
	return secrets
}

func getRotation(resource *terraform.Block, modules terraform.Modules) types.IntValue {

	var days types.IntValue
	for _, r := range modules.GetReferencingResources(resource, "aws_secretsmanager_secret_rotation", "arn") {
		if ruleBlock := r.GetBlock("rotation_rules"); ruleBlock.IsNotNil() {
			days = ruleBlock.GetAttribute("automatically_after_days").AsIntValueOrDefault(0, ruleBlock)
		}
	}
	return days
}

func gettags(resource *terraform.Block) []secretsmanager.Tag {
	var tags []secretsmanager.Tag

	for _, t := range resource.GetBlocks("tags") {
		tags = append(tags, secretsmanager.Tag{
			Metadata: t.GetMetadata(),
		})
	}
	return tags
}
