
### Athena databases and workgroup configurations are created unencrypted at rest by default, they should be encrypted

Athena databases and workspace result sets should be encrypted at rests. These databases and query sets are generally derived from data in S3 buckets and should have the same level of at rest protection.

### Default Severity
{{ severity "HIGH" }}

### Impact
Data can be read if the Athena Database is compromised

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/athena/latest/ug/encryption.html
        