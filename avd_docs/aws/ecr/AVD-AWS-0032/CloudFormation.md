
Do not allow public access in the policy

```yaml
---
Resources:
  GoodExample:
    Type: AWS::ECR::Repository
    Properties:
      RepositoryName: "test-repository"
      ImageTagImmutability: IMMUTABLE
      ImageScanningConfiguration:
        ScanOnPush: false
      EncryptionConfiguration:
        EncryptionType: KMS
        KmsKey: "alias/ecr-key"
      RepositoryPolicyText: 
        Version: "2012-10-17"
        Statement: 
          - 
            Sid: AllowPushPull
            Effect: Allow
            Principal: 
              AWS: 
                - "arn:aws:iam::123456789012:user/Alice"
            Action: 
              - "ecr:GetDownloadUrlForLayer"
              - "ecr:BatchGetImage"
              - "ecr:BatchCheckLayerAvailability"
              - "ecr:PutImage"
              - "ecr:InitiateLayerUpload"
              - "ecr:UploadLayerPart"
              - "ecr:CompleteLayerUpload"
```
