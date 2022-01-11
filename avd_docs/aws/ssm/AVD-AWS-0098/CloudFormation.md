
Use customer managed keys

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example of ingress rule
Resources:
  Secret:
    Type: AWS::SecretsManager::Secret
    Properties:
      Description: "secret"
      KmsKeyId: "my-key-id"
      Name: "blah"
      SecretString: "don't tell anyone"
```
