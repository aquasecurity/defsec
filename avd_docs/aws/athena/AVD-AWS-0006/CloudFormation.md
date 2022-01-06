---
additional_links: []
---

Enable encryption at rest for Athena databases and workgroup configurations

```yaml
---
Resources:
  GoodExample:
    Properties:
      Name: goodExample
      WorkGroupConfiguration:
        ResultConfiguration:
          EncryptionConfiguration:
            EncryptionOption: SSE_KMS
    Type: AWS::Athena::WorkGroup
```
