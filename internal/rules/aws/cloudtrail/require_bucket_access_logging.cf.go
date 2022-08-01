package cloudtrail

var cloudFormationBucketAccessLoggingRequiredGoodExamples = []string{
	`---
Resources:
  GoodExampleTrail:
    Type: AWS::CloudTrail::Trail
    Properties:
      IsLogging: true
      S3BucketName: "my-bucket"
      TrailName: "Cloudtrail"
  GoodExampleBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: "my-bucket"
      LoggingConfiguration:
        DestinationBucketName: logging-bucket
        LogFilePrefix: accesslogs/
`,
}

var cloudFormationBucketAccessLoggingRequiredBadExamples = []string{
	`---
Resources:
  BadExampleTrail:
    Type: AWS::CloudTrail::Trail
    Properties:
      IsLogging: true
      S3BucketName: "my-bucket"
      TrailName: "Cloudtrail"
  BadExampleBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: "my-bucket"
`,
}

var cloudFormationBucketAccessLoggingRequiredLinks = []string{}

var cloudFormationBucketAccessLoggingRequiredRemediationMarkdown = ``
