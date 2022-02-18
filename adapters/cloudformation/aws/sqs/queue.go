package sqs

import (
	"fmt"

	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/providers/aws/iam"
	"github.com/aquasecurity/defsec/providers/aws/sqs"
	"github.com/liamg/iamgo"
)

func getQueues(ctx parser.FileContext) (queues []sqs.Queue) {
	for _, r := range ctx.GetResourceByType("AWS::SQS::Queue") {
		queue := sqs.Queue{
			Metadata: r.Metadata(),
			Encryption: sqs.Encryption{
				KMSKeyID: r.GetStringProperty("KmsMasterKeyId"),
			},
			Policies: []iam.Policy{},
		}
		if policy, err := getPolicy(r.ID(), ctx); err == nil {
			queue.Policies = append(queue.Policies, *policy)
		}
		queues = append(queues, queue)
	}
	return queues
}

func getPolicy(id string, ctx parser.FileContext) (*iam.Policy, error) {
	for _, policyResource := range ctx.GetResourceByType("AWS::SQS::QueuePolicy") {
		documentProp := policyResource.GetProperty("PolicyDocument")
		if documentProp.IsNil() {
			continue
		}
		queuesProp := policyResource.GetProperty("Queues")
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
					Document: iam.Document{
						Metadata: documentProp.Metadata(),
						Parsed:   *parsed,
					},
				}, nil
			}
		}
	}
	return nil, fmt.Errorf("no matching policy found")
}
