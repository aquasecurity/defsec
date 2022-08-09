package sns

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type SNS struct {
	Topics []Topic
}

func NewTopic(arn string, metadata types2.Metadata) Topic {
	return Topic{
		Metadata: metadata,
		ARN:      types2.String(arn, metadata),
		Encryption: Encryption{
			Metadata: metadata,
			KMSKeyID: types2.StringDefault("", metadata),
		},
	}
}

type Topic struct {
	types2.Metadata
	ARN        types2.StringValue
	Encryption Encryption
}

type Encryption struct {
	types2.Metadata
	KMSKeyID types2.StringValue
}
