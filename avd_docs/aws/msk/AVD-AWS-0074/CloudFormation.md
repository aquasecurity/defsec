---
additional_links: []
---

Enable logging

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example
Resources:
  Cluster:
    Type: AWS::MSK::Cluster
    Properties:
      LoggingInfo:
        BrokerLogs:
          S3:
            Enabled: true
```
