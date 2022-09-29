package sqs

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type SQS struct {
	Queues []Queue
}

type Queue struct {
	Metadata   defsecTypes.Metadata
	QueueURL   defsecTypes.StringValue
	Encryption Encryption
	Policies   []iam.Policy
}

type Encryption struct {
	Metadata          defsecTypes.Metadata
	KMSKeyID          defsecTypes.StringValue
	ManagedEncryption defsecTypes.BoolValue
}
