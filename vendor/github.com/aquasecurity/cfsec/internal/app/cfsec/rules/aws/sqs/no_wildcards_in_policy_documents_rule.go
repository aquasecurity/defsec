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
Description: Bad example of queue policy
Resources:
  MyQueue:
    Type: AWS::SQS::Queue
    Properties:
      Name: something
  SampleSQSPolicy: 
    Type: AWS::SQS::QueuePolicy
    Properties: 
      Queues: 
        - !Ref MyQueue
      PolicyDocument: 
        Statement: 
          - 
            Action: 
              - "*" 
            Effect: "Allow"
            Resource: "arn:aws:sqs:us-east-2:444455556666:queue2"
            Principal:  
              AWS: 
                - "111122223333"        
`,
		},

		GoodExample: []string{
			`---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example of queue policy
Resources:
  MyQueue:
    Type: AWS::SQS::Queue
    Properties:
      Name: something
  SampleSQSPolicy: 
    Type: AWS::SQS::QueuePolicy
    Properties: 
      Queues: 
        - Ref: MyQueue
      PolicyDocument: 
        Statement: 
          - 
            Action: 
              - "SQS:SendMessage" 
              - "SQS:ReceiveMessage"
            Effect: "Allow"
            Resource: "arn:aws:sqs:us-east-2:444455556666:queue2"
            Principal:  
              AWS: 
                - "111122223333"        
`,
		},
		Base: sqs.CheckNoWildcardsInPolicyDocuments,
	})
}
