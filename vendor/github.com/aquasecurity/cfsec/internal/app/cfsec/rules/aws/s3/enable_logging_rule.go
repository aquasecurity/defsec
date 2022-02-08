package s3

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/rules"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/aquasecurity/defsec/rules/aws/s3"
)

func init() {
	scanner.RegisterCheckRule(rules.Rule{

		BadExample: []string{
			`---
Resources:
  DisabledEncryptionBucket:
    Properties:
    Type: AWS::S3::Bucket
`,
		},

		GoodExample: []string{
			`---
Resources:
  GoodExample:
    Properties:
      LoggingConfiguration:
        DestinationBucketName: logging-bucket
        LogFilePrefix: accesslogs/
    Type: AWS::S3::Bucket
`,
		},

		Base: s3.CheckLoggingIsEnabled,
	})
}
