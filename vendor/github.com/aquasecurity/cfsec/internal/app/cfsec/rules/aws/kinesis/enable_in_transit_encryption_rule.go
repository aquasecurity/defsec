package kinesis

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/rules"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/aquasecurity/defsec/rules/aws/kinesis"
)

func init() {
	scanner.RegisterCheckRule(rules.Rule{

		BadExample: []string{
			`---
Resources:
  BadExample:
    Type: AWS::Kinesis::Stream
    Properties:
      Name: BadExample
      RetentionPeriodHours: 168
      ShardCount: 3
      Tags:
        -
          Key: Environment 
          Value: Production

`,
		},

		GoodExample: []string{
			`---
Resources:
  GoodExample:
    Type: AWS::Kinesis::Stream
    Properties:
      Name: GoodExample
      RetentionPeriodHours: 168
      ShardCount: 3
      StreamEncryption:
        EncryptionType: KMS
        KeyId: alis/key
      Tags:
        -
          Key: Environment 
          Value: Production
`,
		},
		Base: kinesis.CheckEnableInTransitEncryption,
	})
}
