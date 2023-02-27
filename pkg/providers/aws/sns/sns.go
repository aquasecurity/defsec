package sns

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type SNS struct {
	Topics        []Topic
	Subscriptions []Subscription
}

func NewTopic(arn string, metadata defsecTypes.Metadata) *Topic {
	return &Topic{
		Metadata: metadata,
		ARN:      defsecTypes.String(arn, metadata),
		Policy:   []iam.Policy{},
		Encryption: Encryption{
			Metadata: metadata,
			KMSKeyID: defsecTypes.StringDefault("", metadata),
		},
	}
}

type Topic struct {
	Metadata   defsecTypes.Metadata
	ARN        defsecTypes.StringValue
	Policy     []iam.Policy
	Encryption Encryption
}

type Encryption struct {
	Metadata defsecTypes.Metadata
	KMSKeyID defsecTypes.StringValue
}

type Subscription struct {
	Metadata defsecTypes.Metadata
	Endpoint defsecTypes.StringValue
}
