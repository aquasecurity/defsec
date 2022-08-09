package kinesis

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type Kinesis struct {
	Streams []Stream
}

type Stream struct {
	types2.Metadata
	Encryption Encryption
}

const (
	EncryptionTypeKMS = "KMS"
)

type Encryption struct {
	types2.Metadata
	Type     types2.StringValue
	KMSKeyID types2.StringValue
}
