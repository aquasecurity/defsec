package vpc

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/rules"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/aquasecurity/defsec/rules/aws/sqs"
)

func init() {
	scanner.RegisterCheckRule(rules.Rule{

		BadExample: []string{
			`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example of queue
Resources:
  Queue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: my-queue

`,
		},

		GoodExample: []string{
			`---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example of queue
Resources:
  Queue:
    Type: AWS::SQS::Queue
    Properties:
      KmsMasterKeyId: some-key
      QueueName: my-queue

`,
		},
		Base: sqs.CheckEnableQueueEncryption,
	})
}
