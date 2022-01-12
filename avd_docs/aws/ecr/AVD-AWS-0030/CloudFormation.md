
Enable ECR image scanning

```yaml
---
AWSTemplateFormatVersion: "2010-09-09"
Description: A sample template
Resources:
  GoodExample:
    Type: AWS::ECR::Repository
    Properties:
      RepositoryName: "test-repository"
      ImageTagImmutability: IMMUTABLE
      ImageScanningConfiguration:
        ScanOnPush: true
      EncryptionConfiguration:
        EncryptionType: KMS
        KmsKey: "alias/ecr-key"
```
