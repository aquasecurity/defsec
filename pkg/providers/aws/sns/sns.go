package sns

import (
	"github.com/aquasecurity/defsec/internal/types"
)

type SNS struct {
	types.Metadata
	Topics []Topic
}

type Topic struct {
	types.Metadata
	Encryption Encryption
}

type Encryption struct {
	types.Metadata
	KMSKeyID types.StringValue
}
