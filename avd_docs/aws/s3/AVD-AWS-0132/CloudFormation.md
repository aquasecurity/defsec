
Enable encryption using customer managed keys

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


