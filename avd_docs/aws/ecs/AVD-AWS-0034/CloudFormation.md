
Enable Container Insights

```yaml
---
AWSTemplateFormatVersion: "2010-09-09"
Description: A sample template
Resources:
  GoodExample:
    Type: 'AWS::ECS::Cluster'
    Properties:
      ClusterName: MyCluster
      ClusterSettings:
        - Name: containerInsights
          Value: enabled
```
