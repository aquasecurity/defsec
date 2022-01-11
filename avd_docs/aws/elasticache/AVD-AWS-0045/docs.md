
### Elasticache Replication Group stores unencrypted data at-rest.

Data stored within an Elasticache replication node should be encrypted to ensure sensitive data is kept private.

### Default Severity
{{ severity "HIGH" }}

### Impact
At-rest data in the Replication Group could be compromised if accessed.

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/at-rest-encryption.html
        