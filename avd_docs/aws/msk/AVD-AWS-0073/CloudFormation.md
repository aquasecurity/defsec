
Enable in transit encryption

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example
Resources:
  Cluster:
    Type: AWS::MSK::Cluster
    Properties:
      EncryptionInfo:
        EncryptionInTransit:
          ClientBroker: "TLS"
```
