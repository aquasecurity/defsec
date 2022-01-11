
### Redis cluster should have backup retention turned on

Redis clusters should have a snapshot retention time to ensure that they are backed up and can be restored if required.

### Default Severity
{{ severity "MEDIUM" }}

### Impact
Without backups of the redis cluster recovery is made difficult

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/backups-automatic.html
        