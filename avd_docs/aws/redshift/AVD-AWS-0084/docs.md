
### Redshift clusters should use at rest encryption

Redshift clusters that contain sensitive data or are subject to regulation should be encrypted at rest to prevent data leakage should the infrastructure be compromised.

### Default Severity
{{ severity "HIGH" }}

### Impact
Data may be leaked if infrastructure is compromised

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-db-encryption.html
        