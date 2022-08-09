package kinesis

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Kinesis struct {
	Streams []Stream
}

type Stream struct {
	defsecTypes.Metadata
	Encryption Encryption
}

const (
	EncryptionTypeKMS = "KMS"
)

type Encryption struct {
	defsecTypes.Metadata
	Type     defsecTypes.StringValue
	KMSKeyID defsecTypes.StringValue
}
