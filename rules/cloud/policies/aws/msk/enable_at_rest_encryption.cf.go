package msk

var cloudFormationEnableAtRestEncryptionGoodExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example
Resources:
  Cluster:
    Type: AWS::MSK::Cluster
    Properties:
      EncryptionInfo:
        EncryptionAtRest:
          DataVolumeKMSKeyId: "foo-bar-key"
`,
}

var cloudFormationEnableAtRestEncryptionBadExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example
Resources:
  Cluster:
    Type: AWS::MSK::Cluster
    Properties:
`,
}

var cloudFormationEnableAtRestEncryptionLinks = []string{}

var cloudFormationEnableAtRestEncryptionRemediationMarkdown = ``
