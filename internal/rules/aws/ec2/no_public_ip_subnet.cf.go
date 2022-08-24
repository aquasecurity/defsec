package ec2

var cloudFormationNoPublicIpSubnetGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Properties:
      VpcId: vpc-123456
    Type: AWS::EC2::Subnet
`,
}

var cloudFormationNoPublicIpSubnetBadExamples = []string{
	`---
Resources:
  BadExample:
    Properties:
      MapPublicIpOnLaunch: true
      VpcId: vpc-123456
    Type: AWS::EC2::Subnet
`,
}

var cloudFormationNoPublicIpSubnetLinks = []string{}

var cloudFormationNoPublicIpSubnetRemediationMarkdown = ``
