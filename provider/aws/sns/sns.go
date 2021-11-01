package sns

import "github.com/aquasecurity/defsec/types"

type SNS struct {
	Topics []Topic
}

type Topic struct {
	types.Metadata
	Encryption Encryption
}

type Encryption struct {
	KMSKeyID types.StringValue
}
