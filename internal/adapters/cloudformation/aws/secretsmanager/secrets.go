package secretsmanager

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/secretsmanager"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	"github.com/aquasecurity/defsec/pkg/types"
)

func getSecrets(ctx parser.FileContext) []secretsmanager.Secret {
	var secrets []secretsmanager.Secret

	var days types.IntValue
	for _, rotation := range ctx.GetResourcesByType("AWS::SecretsManager::RotationSchedule") {
		days = rotation.GetIntProperty("RotationRules.AutomaticallyAfterDays")
	}

	for _, r := range ctx.GetResourcesByType("AWS::SecretsManager::Secret") {

		var tags []secretsmanager.Tag
		for _, t := range r.GetProperty("Tags").AsList() {
			tags = append(tags, secretsmanager.Tag{
				Metadata: t.Metadata(),
			})
		}

		secrets = append(secrets, secretsmanager.Secret{
			Metadata:               r.Metadata(),
			KmsKeyId:               r.GetStringProperty("KmsKeyId"),
			Arn:                    r.GetStringProperty("Arn"),
			Tags:                   tags,
			RotationEnabled:        types.BoolDefault(false, r.Metadata()),
			AutomaticallyAfterDays: days,
		})
	}
	return secrets
}
