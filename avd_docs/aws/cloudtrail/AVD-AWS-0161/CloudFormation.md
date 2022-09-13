
Restrict public access to the S3 bucket

```yaml---
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

```


