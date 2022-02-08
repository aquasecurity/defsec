package vpc

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/rules"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/aquasecurity/defsec/rules/aws/sns"
)

func init() {
	scanner.RegisterCheckRule(rules.Rule{

		BadExample: []string{
			`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example of topic
Resources:
  Queue:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: blah

`,
		},

		GoodExample: []string{
			`---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example of topic
Resources:
  Queue:
    Type: AWS::SQS::Topic
    Properties:
      TopicName: blah
      KmsMasterKeyId: some-key

`,
		},
		Base: sns.CheckEnableTopicEncryption,
	})
}
