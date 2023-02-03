package cloudtrail

var cloudFormationNoPublicLogAccessGoodExamples = []string{
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
      AccessControl: Private
`,
}

var cloudFormationNoPublicLogAccessBadExamples = []string{
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
      AccessControl: AuthenticatedRead
`,
}

var cloudFormationNoPublicLogAccessLinks = []string{}

var cloudFormationNoPublicLogAccessRemediationMarkdown = ``
