package ssm

import "github.com/aquasecurity/defsec/types"

type SSM struct {
	Secrets []Secret
}

type Secret struct {
	types.Metadata
	KMSKeyID types.StringValue
}
