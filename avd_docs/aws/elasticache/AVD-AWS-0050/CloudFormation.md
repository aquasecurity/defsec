
Configure snapshot retention for redis cluster

```yaml
---
Resources:
  GoodExample:
    Type: AWS::ElastiCache::CacheCluster
    Properties:
      AZMode: cross-az
      CacheNodeType: cache.m3.medium
      Engine: redis
      NumCacheNodes: '3'
      SnapshotRetentionLimit: 7
      PreferredAvailabilityZones:
        - us-west-2a
        - us-west-2a
        - us-west-2b
```
