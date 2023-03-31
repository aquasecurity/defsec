package cloudtrail

var cloudFormationEnsureCloudwatchIntegrationGoodExamples = []string{
	`---
Resources:
  GoodExampleTrail:
    Type: AWS::CloudTrail::Trail
    Properties:
      TrailName: "Cloudtrail"
      CloudWatchLogsLogGroupArn: "arn:aws:logs:us-east-1:123456789012:log-group:CloudTrail/DefaultLogGroup:*"
`,
}

var cloudFormationEnsureCloudwatchIntegrationBadExamples = []string{
	`---
Resources:
  BadExampleTrail:
    Type: AWS::CloudTrail::Trail
    Properties:
      TrailName: "Cloudtrail"
`,
}

var cloudFormationEnsureCloudwatchIntegrationLinks = []string{}

var cloudFormationEnsureCloudwatchIntegrationRemediationMarkdown = ``
