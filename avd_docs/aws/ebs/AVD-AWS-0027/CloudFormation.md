---
additional_links: []
---

Enable encryption using customer managed keys

```yaml
---
Resources:
  GoodExample:
    Type: AWS::EC2::Volume
    Properties: 
      Size: 100
      Encrypted: true
      KmsKeyId: "alias/volumeEncrypt"
    DeletionPolicy: Snapshot
```
