package ssm

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type SSM struct {
	Secrets []Secret
}

type Secret struct {
	types2.Metadata
	KMSKeyID types2.StringValue
}

const DefaultKMSKeyID = "alias/aws/secretsmanager"
