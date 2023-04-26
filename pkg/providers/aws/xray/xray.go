package xray

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Xray struct {
	EncryptionConfig Configuration
}

type Configuration struct {
	Metadata defsecTypes.Metadata
	KeyId    defsecTypes.StringValue
}
