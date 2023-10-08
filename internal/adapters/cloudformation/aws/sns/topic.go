package sns

import (
	"fmt"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"

	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	"github.com/aquasecurity/defsec/pkg/providers/aws/sns"

	"github.com/liamg/iamgo"
)

func getTopics(ctx parser.FileContext) (topics []sns.Topic) {
	for _, r := range ctx.GetResourcesByType("AWS::SNS::Topic") {

		topic := sns.Topic{
			Metadata: r.Metadata(),
			ARN:      defsecTypes.StringDefault("", r.Metadata()),
			Policy:   []iam.Policy{},
			Encryption: sns.Encryption{
				Metadata: r.Metadata(),
				KMSKeyID: r.GetStringProperty("KmsMasterKeyId"),
			},
		}
		if policy, err := getPolicy(r.ID(), ctx); err == nil {
			topic.Policy = append(topic.Policy, *policy)
		}

		topics = append(topics, topic)
	}
	return topics
}

func getSubscriptions(ctx parser.FileContext) (subcriptions []sns.Subscription) {
	for _, r := range ctx.GetResourcesByType("AWS::SNS::Subscription") {
		subcription := sns.Subscription{
			Metadata: r.Metadata(),
			Endpoint: r.GetStringProperty("Endpoint"),
		}
		subcriptions = append(subcriptions, subcription)
	}
	return subcriptions
}

func getPolicy(id string, ctx parser.FileContext) (*iam.Policy, error) {
	for _, policyResource := range ctx.GetResourcesByType("AWS::SNS::TopicPolicy") {
		documentProp := policyResource.GetProperty("PolicyDocument")
		if documentProp.IsNil() {
			continue
		}
		queuesProp := policyResource.GetProperty("Topics")
		if queuesProp.IsNil() {
			continue
		}
		for _, queueRef := range queuesProp.AsList() {
			if queueRef.IsString() && queueRef.AsString() == id {
				raw := documentProp.GetJsonBytes()
				parsed, err := iamgo.Parse(raw)
				if err != nil {
					continue
				}
				return &iam.Policy{
					Metadata: documentProp.Metadata(),
					Name:     defsecTypes.StringDefault("", documentProp.Metadata()),
					Document: iam.Document{
						Metadata: documentProp.Metadata(),
						Parsed:   *parsed,
					},
					Builtin: defsecTypes.Bool(false, documentProp.Metadata()),
				}, nil
			}
		}
	}
	return nil, fmt.Errorf("no matching policy found")
}
