package ecr

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/rules"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/aquasecurity/defsec/rules/aws/ecr"
)

func init() {

	scanner.RegisterCheckRule(rules.Rule{

		BadExample: []string{`---
Resources:
  BadExample:
    Type: AWS::ECR::Repository
    Properties:
      RepositoryName: "test-repository"
      ImageScanningConfiguration:
        ScanOnPush: false
`},
		GoodExample: []string{`---
Resources:
  GoodExample:
    Type: AWS::ECR::Repository
    Properties:
      RepositoryName: "test-repository"
      ImageTagMutability: IMMUTABLE
      ImageScanningConfiguration:
        ScanOnPush: false
      EncryptionConfiguration:
        EncryptionType: KMS
        KmsKey: "alias/ecr-key"
`},
		Base: ecr.CheckEnforceImmutableRepository,
	},
	)

}
