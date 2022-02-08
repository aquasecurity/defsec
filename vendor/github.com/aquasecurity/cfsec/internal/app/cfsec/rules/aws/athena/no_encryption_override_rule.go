package athena

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/rules"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/aquasecurity/defsec/rules/aws/athena"
)

func init() {
	scanner.RegisterCheckRule(rules.Rule{

		BadExample: []string{
			`---
Resources:
  BadExample:
    Properties:
      Name: badExample
      WorkGroupConfiguration:
        EnforceWorkGroupConfiguration: false
        ResultConfiguration:
          EncryptionConfiguration:
            EncryptionOption: SSE_KMS
    Type: AWS::Athena::WorkGroup
`,
		},

		GoodExample: []string{
			`---
Resources:
  GoodExample:
    Properties:
      Name: goodExample
      WorkGroupConfiguration:
        EnforceWorkGroupConfiguration: true
        ResultConfiguration:
          EncryptionConfiguration:
            EncryptionOption: SSE_KMS
    Type: AWS::Athena::WorkGroup
`,
		},

		Base: athena.CheckNoEncryptionOverride,
	})
}
