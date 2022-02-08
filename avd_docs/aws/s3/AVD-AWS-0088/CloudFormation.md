
Configure bucket encryption

```yaml
Resources:
  GoodExample:
    Properties:
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - BucketKeyEnabled: true
            ServerSideEncryptionByDefault:
              KMSMasterKeyID: kms-arn
              SSEAlgorithm: aws:kms
    Type: AWS::S3::Bucket
```
