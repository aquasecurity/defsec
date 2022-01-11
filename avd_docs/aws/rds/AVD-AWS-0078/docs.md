
### Encryption for RDS Performance Insights should be enabled.

When enabling Performance Insights on an RDS cluster or RDS DB Instance, and encryption key should be provided.

The encryption key specified in `performance_insights_kms_key_id` references a KMS ARN

### Default Severity
{{ severity "HIGH" }}

### Impact
Data can be read from the RDS Performance Insights if it is compromised

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.htm
        