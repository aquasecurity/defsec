package sqs

import (
	"github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
)

type SQS struct {
	Queues []Queue
}

type Queue struct {
	types.Metadata
	QueueURL   types.StringValue
	Encryption Encryption
	Policies   []iam.Policy
}

func NewQueue(metadata types.Metadata) Queue {
	return Queue{
		Metadata: metadata,
		QueueURL: types.StringDefault("", metadata),
		Policies: []iam.Policy{},
		Encryption: Encryption{
			Metadata:          metadata,
			KMSKeyID:          types.StringDefault("", metadata),
			ManagedEncryption: types.BoolDefault(false, metadata),
		},
	}
}

type Encryption struct {
	types.Metadata
	KMSKeyID          types.StringValue
	ManagedEncryption types.BoolValue
}
