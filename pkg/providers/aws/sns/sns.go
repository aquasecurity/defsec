package sns

import (
	"github.com/aquasecurity/defsec/internal/types"
)

type SNS struct {
	Topics []Topic
}

func NewTopic(arn string, metadata types.Metadata) Topic {
	return Topic{
		Metadata: metadata,
		TopicARN: types.String(arn, metadata),
		Encryption: Encryption{
			Metadata: metadata,
			KMSKeyID: types.StringDefault("", metadata),
		},
	}
}

type Topic struct {
	types.Metadata
	TopicARN   types.StringValue
	Encryption Encryption
}

type Encryption struct {
	types.Metadata
	KMSKeyID types.StringValue
}
