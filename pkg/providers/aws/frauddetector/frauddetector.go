package frauddetector

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Frauddetector struct {
	KmsKey KmsKey
}

type KmsKey struct {
	Metadata            defsecTypes.Metadata
	KmsEncryptionKeyArn defsecTypes.StringValue
}
