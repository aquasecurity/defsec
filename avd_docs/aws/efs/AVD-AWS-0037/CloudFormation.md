
Enable encryption for EFS

```yaml---
Resources:
  GoodExample:
    Type: AWS::EFS::FileSystem
    Properties:
      BackupPolicy:
        Status: ENABLED
      LifecyclePolicies:
        - TransitionToIA: AFTER_60_DAYS
      PerformanceMode: generalPurpose
      Encrypted: true
      ThroughputMode: bursting

```


