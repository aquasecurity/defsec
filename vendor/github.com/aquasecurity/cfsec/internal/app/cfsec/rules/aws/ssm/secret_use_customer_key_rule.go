package vpc

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/rules"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/aquasecurity/defsec/rules/aws/ssm"
)

func init() {
	scanner.RegisterCheckRule(rules.Rule{

		BadExample: []string{
			`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example of secret
Resources:
  BadSecret:
    Type: AWS::SecretsManager::Secret
    Properties:
      Description: "secret"
      Name: "blah"
      SecretString: "don't tell anyone"
`,
		},

		GoodExample: []string{
			`---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example of ingress rule
Resources:
  Secret:
    Type: AWS::SecretsManager::Secret
    Properties:
      Description: "secret"
      KmsKeyId: "my-key-id"
      Name: "blah"
      SecretString: "don't tell anyone"
`,
		},
		Base: ssm.CheckSecretUseCustomerKey,
	})
}
