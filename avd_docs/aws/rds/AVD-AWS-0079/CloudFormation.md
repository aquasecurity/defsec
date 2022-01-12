
Enable encryption for RDS clusters

```yaml
---
AWSTemplateFormatVersion: "2010-09-09"
Description: A sample template
AWSTemplateFormatVersion: 2010-09-09
Description: Good example of rds sgr
Resources:
  Cluster:
    Type: AWS::RDS::DBCluster
    Properties:
      StorageEncrypted: true
      KmsKeyId: "something"
```
