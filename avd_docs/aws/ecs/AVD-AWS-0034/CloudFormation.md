---
additional_links: []
---

Enable Container Insights

```yaml
---
Resources:
  GoodExample:
    Type: 'AWS::ECS::Cluster'
    Properties:
      ClusterName: MyCluster
      ClusterSettings:
        - Name: containerInsights
          Value: enabled
```
