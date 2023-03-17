package secretsmanager

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type SecretsManager struct {
	Secrets []Secret
}

type Secret struct {
	Metadata               defsecTypes.Metadata
	Arn                    defsecTypes.StringValue
	KmsKeyId               defsecTypes.StringValue
	RotationEnabled        defsecTypes.BoolValue
	AutomaticallyAfterDays defsecTypes.IntValue
	Tags                   []Tag
}

type Tag struct {
	Metadata defsecTypes.Metadata
}
