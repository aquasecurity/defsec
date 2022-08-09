package sqs

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type SQS struct {
	Queues []Queue
}

type Queue struct {
	defsecTypes.Metadata
	QueueURL   defsecTypes.StringValue
	Encryption Encryption
	Policies   []iam.Policy
}

func NewQueue(metadata defsecTypes.Metadata, queueUrl string) Queue {
	return Queue{
		Metadata: metadata,
		QueueURL: defsecTypes.StringDefault(queueUrl, metadata),
		Policies: []iam.Policy{},
		Encryption: Encryption{
			Metadata:          metadata,
			KMSKeyID:          defsecTypes.StringDefault("", metadata),
			ManagedEncryption: defsecTypes.BoolDefault(false, metadata),
		},
	}
}

type Encryption struct {
	defsecTypes.Metadata
	KMSKeyID          defsecTypes.StringValue
	ManagedEncryption defsecTypes.BoolValue
}
