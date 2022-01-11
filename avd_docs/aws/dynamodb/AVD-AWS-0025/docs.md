
### DynamoDB tables should use at rest encryption with a Customer Managed Key

DynamoDB tables are encrypted by default using AWS managed encryption keys. To increase control of the encryption and control the management of factors like key rotation, use a Customer Managed Key.

### Default Severity
{{ severity "LOW" }}

### Impact
Using AWS managed keys does not allow for fine grained control

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/EncryptionAtRest.html
        