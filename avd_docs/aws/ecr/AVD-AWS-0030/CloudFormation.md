
Enable ECR image scanning

```yaml---
Resources:
  GoodExample:
    Type: AWS::ECR::Repository
    Properties:
      RepositoryName: "test-repository"
      ImageTagImmutability: IMMUTABLE
      ImageScanningConfiguration:
        ScanOnPush: True
      EncryptionConfiguration:
        EncryptionType: KMS
        KmsKey: "alias/ecr-key"

```


