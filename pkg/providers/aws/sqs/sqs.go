package sqs

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type SQS struct {
	Queues []Queue
}

type Queue struct {
	types2.Metadata
	QueueURL   types2.StringValue
	Encryption Encryption
	Policies   []iam.Policy
}

func NewQueue(metadata types2.Metadata, queueUrl string) Queue {
	return Queue{
		Metadata: metadata,
		QueueURL: types2.StringDefault(queueUrl, metadata),
		Policies: []iam.Policy{},
		Encryption: Encryption{
			Metadata:          metadata,
			KMSKeyID:          types2.StringDefault("", metadata),
			ManagedEncryption: types2.BoolDefault(false, metadata),
		},
	}
}

type Encryption struct {
	types2.Metadata
	KMSKeyID          types2.StringValue
	ManagedEncryption types2.BoolValue
}
