
Enable encryption at rest

```yaml---
Resources:
  GoodExample:
    Type: AWS::CloudTrail::Trail
    Properties:
      IsLogging: true
      IsMultiRegionTrail: true
      KmsKeyId: "alias/CloudtrailKey"
      S3BucketName: "CloudtrailBucket"
      S3KeyPrefix: "/trailing"
      TrailName: "Cloudtrail"

```


