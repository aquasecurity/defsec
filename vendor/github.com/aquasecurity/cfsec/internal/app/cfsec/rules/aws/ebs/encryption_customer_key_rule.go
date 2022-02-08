package ebs

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/rules"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/aquasecurity/defsec/rules/aws/ebs"
)

func init() {

	scanner.RegisterCheckRule(rules.Rule{
		BadExample: []string{`---
Resources:
  BadExample:
    Type: AWS::EC2::Volume
    Properties:
      Size: 100
      AvailabilityZone: !GetAtt Ec2Instance.AvailabilityZone
    DeletionPolicy: Snapshot
`},
		GoodExample: []string{`---
Resources:
  GoodExample:
    Type: AWS::EC2::Volume
    Properties: 
      Size: 100
      Encrypted: true
      KmsKeyId: "alias/volumeEncrypt"
    DeletionPolicy: Snapshot
`},
		Base: ebs.CheckEncryptionCustomerKey,
	})
}
