
Deploy Redshift cluster into a non default VPC

```yaml---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example of redshift cluster
Resources:
  Queue:
    Type: AWS::Redshift::Cluster
    Properties:
      ClusterSubnetGroupName: "my-subnet-group"


```


