
Only use immutable images in ECR

```yaml---
Resources:
  GoodExample:
    Type: AWS::ECR::Repository
    Properties:
      RepositoryName: "test-repository"
      ImageTagMutability: IMMUTABLE
      ImageScanningConfiguration:
        ScanOnPush: false
      EncryptionConfiguration:
        EncryptionType: KMS
        KmsKey: "alias/ecr-key"

```


