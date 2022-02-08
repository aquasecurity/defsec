package sqs

import (
	"fmt"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/util"
	"github.com/aquasecurity/defsec/provider/aws/iam"
	"github.com/aquasecurity/defsec/provider/aws/sqs"
)

func getQueues(ctx parser.FileContext) (queues []sqs.Queue) {
	for _, r := range ctx.GetResourceByType("AWS::SQS::Queue") {
		queue := sqs.Queue{
			Metadata: r.Metadata(),
			Encryption: sqs.Encryption{
				KMSKeyID: r.GetStringProperty("KmsMasterKeyId"),
			},
			Policy: iam.PolicyDocument{},
		}
		if policy, err := getPolicy(r.ID(), ctx); err == nil {
			queue.Policy = *policy
		}
		queues = append(queues, queue)
	}
	return queues
}

func getPolicy(id string, ctx parser.FileContext) (*iam.PolicyDocument, error) {
	for _, policyResource := range ctx.GetResourceByType("AWS::SQS::QueuePolicy") {
		documentProp := policyResource.GetProperty("PolicyDocument")
		if documentProp.IsNil() {
			continue
		}
		policyBytes := util.GetJsonBytes(documentProp, policyResource.SourceFormat())
		doc, err := iam.ParsePolicyDocument(policyBytes, documentProp.Metadata())
		if err != nil {
			continue
		}
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
