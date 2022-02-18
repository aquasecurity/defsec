
Encryption should be enabled for an RDS Aurora cluster. 

When enabling encryption by setting the kms_key_id, the storage_encrypted must also be set to true.

### Impact
Data can be read from the RDS cluster if it is compromised

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html
        