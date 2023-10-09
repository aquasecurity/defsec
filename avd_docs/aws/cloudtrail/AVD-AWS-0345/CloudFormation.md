
Enable include global service events for Cloudtrail

```yaml---
Resources:
  GoodExampleTrail:
    Type: AWS::CloudTrail::Trail
    Properties:
	    IncludeGlobalServiceEvents: true
      S3BucketName: "my-bucket"
      TrailName: "Cloudtrail"

```


