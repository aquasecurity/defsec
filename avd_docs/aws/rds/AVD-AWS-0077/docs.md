
### RDS Cluster and RDS instance should have backup retention longer than default 1 day

RDS backup retention for clusters defaults to 1 day, this may not be enough to identify and respond to an issue. Backup retention periods should be set to a period that is a balance on cost and limiting risk.

### Default Severity
{{ severity "MEDIUM" }}

### Impact
Potential loss of data and short opportunity for recovery

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html#USER_WorkingWithAutomatedBackups.BackupRetention
        