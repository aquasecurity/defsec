package ssm

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type SSM struct {
	Secrets []Secret
}

type Secret struct {
	Metadata defsecTypes.Metadata
	KMSKeyID defsecTypes.StringValue
}

const DefaultKMSKeyID = "alias/aws/secretsmanager"
