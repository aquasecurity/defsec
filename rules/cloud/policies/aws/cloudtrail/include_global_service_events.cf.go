package cloudtrail

var cloudFormationIncludeGlobalServiceEventsGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Type: AWS::CloudTrail::Trail
    Properties:
      IncludeGlobalServiceEvents: true
      S3BucketName: "my-bucket"
      TrailName: "Cloudtrail"
`,
}

var cloudFormationIncludeGlobalServiceEventsBadExamples = []string{
	`---
Resources:
  BadExample:
    Type: AWS::CloudTrail::Trail
    Properties:
      IncludeGlobalServiceEvents: false
      S3BucketName: "my-bucket"
      TrailName: "Cloudtrail"
`,
}

var cloudFormationIncludeGlobalServiceEventsLinks = []string{}

var cloudFormationIncludeGlobalServiceEventsRemediationMarkdown = ``
