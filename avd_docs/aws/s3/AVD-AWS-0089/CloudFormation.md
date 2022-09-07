
Add a logging block to the resource to enable access logging

```yaml---
Resources:
  GoodExample:
    Properties:
      LoggingConfiguration:
        DestinationBucketName: logging-bucket
        LogFilePrefix: accesslogs/
    Type: AWS::S3::Bucket

```
```yaml---
Resources:
  MyS3Bucket:
    Type: AWS::S3::Bucket
    DeletionPolicy: Retain
    UpdateReplacePolicy: Retain
    Properties:
      BucketName: !Sub my-s3-bucket-${BucketSuffix}
      LoggingConfiguration:
        DestinationBucketName: !FindInMap [EnvironmentMapping, s3, logging]
        LogFilePrefix: !Sub s3-logs/AWSLogs/${AWS::AccountId}/my-s3-bucket-${BucketSuffix}
      AccessControl: Private
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true

```


