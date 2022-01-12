
Enable encryption using CMK

```yaml
---
AWSTemplateFormatVersion: "2010-09-09"
Description: A sample template
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example of redshift cluster
Resources:
  Queue:
    Type: AWS::Redshift::Cluster
    Properties:
      Encrypted: true
      KmsKeyId: "something"
```
