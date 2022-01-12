
### DocumentDB encryption should use Customer Managed Keys

Encryption using AWS keys provides protection for your DocumentDB underlying storage. To increase control of the encryption and manage factors like rotation use customer managed keys.

### Impact
Using AWS managed keys does not allow for fine grained control

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/documentdb/latest/developerguide/security.encryption.ssl.public-key.html
        