
### Elasticache Replication Group uses unencrypted traffic.

Traffic flowing between Elasticache replication nodes should be encrypted to ensure sensitive data is kept private.

### Default Severity
{{ severity "HIGH" }}

### Impact
In transit data in the Replication Group could be read if intercepted

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/in-transit-encryption.html
        