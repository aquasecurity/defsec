
Enable export logs

```yaml
---
AWSTemplateFormatVersion: "2010-09-09"
Description: A sample template
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example
Resources:
  Cluster:
    Type: AWS::Neptune::DBCluster
    Properties:
      EnableCloudwatchLogsExports:
        - audit
```
