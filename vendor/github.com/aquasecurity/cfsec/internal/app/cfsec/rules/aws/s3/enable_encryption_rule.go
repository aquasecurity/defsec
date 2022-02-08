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
  BadExample:
    Properties:
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - BucketKeyEnabled: false
            ServerSideEncryptionByDefault:
              KMSMasterKeyID: asdf
              SSEAlgorithm: asdf
    Type: AWS::S3::Bucket
`,
		},

		GoodExample: []string{
			`
Resources:
  GoodExample:
    Properties:
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - BucketKeyEnabled: true
            ServerSideEncryptionByDefault:
              SSEAlgorithm: AES256
    Type: AWS::S3::Bucket
`,
		},

		Base: s3.CheckEncryptionIsEnabled,
	})
}
