
Enforce the configuration to prevent client overrides

```yaml
---
AWSTemplateFormatVersion: "2010-09-09"
Description: A sample template
Resources:
  GoodExample:
    Properties:
      Name: goodExample
      WorkGroupConfiguration:
        EnforceWorkGroupConfiguration: true
        ResultConfiguration:
          EncryptionConfiguration:
            EncryptionOption: SSE_KMS
    Type: AWS::Athena::WorkGroup
```
