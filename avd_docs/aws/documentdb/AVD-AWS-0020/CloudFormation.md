---
additional_links: []
---

Enable export logs

```yaml
---
Resources:
  GoodExample:
    Type: "AWS::DocDB::DBCluster"
    Properties:
      BackupRetentionPeriod : 8
      DBClusterIdentifier : "sample-cluster"
      DBClusterParameterGroupName : "default.docdb3.6"
      KmsKeyId : "your-kms-key-id"
      EnableCloudwatchLogsExports:
      - audit
      - profiler
  InstanceInstanceExample:
    Type: "AWS::DocDB::DBInstance"
    Properties:
      AutoMinorVersionUpgrade: true
      AvailabilityZone: "us-east-1c"
      DBClusterIdentifier: "sample-cluster"
      DBInstanceClass: "db.r5.large"
      DBInstanceIdentifier: "sample-cluster-instance-0"
      PreferredMaintenanceWindow: "sat:06:54-sat:07:24"
```
