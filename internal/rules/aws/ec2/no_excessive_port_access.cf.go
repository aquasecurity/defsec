package ec2

var cloudFormationNoExcessivePortAccessGoodExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example of excessive ports
Resources: 
  NetworkACL:
    Type: AWS::EC2::NetworkAcl
    Properties:
      VpcId: "something"
	  RuleAction: "allow"
  Rule:
    Type: AWS::EC2::NetworkAclEntry
    Properties:
      RuleAction: "allow"
      NetworkAclId:
        Ref: NetworkACL
      Protocol: 6
`,
}

var cloudFormationNoExcessivePortAccessBadExamples = []string{
	`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example of excessive ports
Resources:
  NetworkACL:
    Type: AWS::EC2::NetworkAcl
    Properties:
      VpcId: "something"
      RuleAction: "allow"
  Rule:
    Type: AWS::EC2::NetworkAclEntry
    Properties:
      NetworkAclId:
        Ref: NetworkACL
      Protocol: -1
      RuleAction: "allow"
`,
}

var cloudFormationNoExcessivePortAccessLinks = []string{}

var cloudFormationNoExcessivePortAccessRemediationMarkdown = ``
