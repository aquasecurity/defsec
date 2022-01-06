---
additional_links: []
---

Enable export logs

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example
Resources:
  Cluster:
    Type: AWS::Neptune::DBCluster
    Properties:
      EnableCloudwatchLogsExports:
        - audit
```
