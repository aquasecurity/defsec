
DynamoDB tables are encrypted by default using AWS managed encryption keys. To increase control of the encryption and control the management of factors like key rotation, use a Customer Managed Key.

### Impact
Using AWS managed keys does not allow for fine grained control

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/EncryptionAtRest.html
        