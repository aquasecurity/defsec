package ec2

var cloudformationASEnforceHttpTokenImdsGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Type: AWS::AutoScaling::LaunchConfiguration
    Properties:
      MetadataOptions:
        HttpTokens: required
        HttpEndpoint: enabled
 `,
}

var cloudformationASEnforceHttpTokenImdsBadExamples = []string{
	`---
Resources:
  BadExample:
    Type: AWS::AutoScaling::LaunchConfiguration
    Properties:
      MetadataOptions:
        HttpTokens: optional
        HttpEndpoint: enabled
 `,
}

var cloudformationASEnforceHttpTokenImdsLinks = []string{}

var cloudformationASEnforceHttpTokenImdsRemediationMarkdown = ``
