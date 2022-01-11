
### RDS encryption has not been enabled at a DB Instance level.

Encryption should be enabled for an RDS Database instances. 

When enabling encryption by setting the kms_key_id.

### Default Severity
{{ severity "HIGH" }}

### Impact
Data can be read from RDS instances if compromised

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html
        