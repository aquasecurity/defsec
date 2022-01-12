
Enable encryption using customer managed keys

```yaml
---
AWSTemplateFormatVersion: "2010-09-09"
Description: A sample template
Resources:
  GoodExample:
    Type: AWS::EC2::Volume
    Properties: 
      Size: 100
      Encrypted: true
      KmsKeyId: "alias/volumeEncrypt"
    DeletionPolicy: Snapshot
```
