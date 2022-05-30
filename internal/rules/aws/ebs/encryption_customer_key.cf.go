package ebs

var cloudFormationEncryptionCustomerKeyGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Type: AWS::EC2::Volume
    Properties: 
      Size: 100
      Encrypted: true
      KmsKeyId: "alias/volumeEncrypt"
    DeletionPolicy: Snapshot
`,
	`---
Resources:
  GoodExample:
    Type: AWS::EC2::Volume
    Properties: 
      Size: 100
      Encrypted: true
      KmsKeyId: !ImportValue "MyStack:Key"
    DeletionPolicy: Snapshot
`,
}

var cloudFormationEncryptionCustomerKeyBadExamples = []string{
	`---
Resources:
  BadExample:
    Type: AWS::EC2::Volume
    Properties:
      Size: 100
      AvailabilityZone: !GetAtt Ec2Instance.AvailabilityZone
    DeletionPolicy: Snapshot
`,
}

var cloudFormationEncryptionCustomerKeyLinks = []string{}

var cloudFormationEncryptionCustomerKeyRemediationMarkdown = ``
