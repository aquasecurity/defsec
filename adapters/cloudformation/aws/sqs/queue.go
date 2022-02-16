package sqs

import (
	"fmt"

	"github.com/aquasecurity/defsec/provider/aws/sqs"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
	"github.com/aquasecurity/trivy-config-parsers/types"
)

func getQueues(ctx parser.FileContext) (queues []sqs.Queue) {
	for _, r := range ctx.GetResourceByType("AWS::SQS::Queue") {
		queue := sqs.Queue{
			Metadata: r.Metadata(),
			Encryption: sqs.Encryption{
				KMSKeyID: r.GetStringProperty("KmsMasterKeyId"),
			},
			Policies: []types.StringValue{},
		}
		if policy, err := getPolicy(r.ID(), ctx); err == nil {
			queue.Policies = append(queue.Policies, policy)
		}
		queues = append(queues, queue)
	}
	return queues
}

func getPolicy(id string, ctx parser.FileContext) (types.StringValue, error) {
	for _, policyResource := range ctx.GetResourceByType("AWS::SQS::QueuePolicy") {
		documentProp := policyResource.GetProperty("PolicyDocument")
		if documentProp.IsNil() {
			continue
		}
		doc := types.String(documentProp.GetJsonBytesAsString(), documentProp.Metadata())
		queuesProp := policyResource.GetProperty("Queues")
		if queuesProp.IsNil() {
			continue
		}
		for _, queueRef := range queuesProp.AsList() {
			if queueRef.IsString() && queueRef.AsString() == id {
				return doc, nil
			}
		}
	}
	return nil, fmt.Errorf("no matching policy found")
}
