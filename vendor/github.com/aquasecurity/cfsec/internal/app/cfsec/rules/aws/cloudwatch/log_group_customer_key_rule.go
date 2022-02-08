package cloudwatch

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/rules"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/aquasecurity/defsec/rules/aws/cloudwatch"
)

func init() {

	scanner.RegisterCheckRule(rules.Rule{

		BadExample: []string{`---
Resources:
  BadExample:
    Type: AWS::Logs::LogGroup
    Properties:
      KmsKeyId: ""
      LogGroupName: "aws/lambda/badExample"
      RetentionInDays: 30
`},
		GoodExample: []string{`---
Resources:
  GoodExample:
    Type: AWS::Logs::LogGroup
    Properties:
      KmsKeyId: "arn:aws:kms:us-west-2:111122223333:key/lambdalogging"
      LogGroupName: "aws/lambda/goodExample"
      RetentionInDays: 30
`},
		Base: cloudwatch.CheckLogGroupCustomerKey,
	},
	)
}
