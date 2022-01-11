
### Secrets Manager should use customer managed keys

Secrets Manager encrypts secrets by default using a default key created by AWS. To ensure control and granularity of secret encryption, CMK's should be used explicitly.

### Default Severity
{{ severity "LOW" }}

### Impact
Using AWS managed keys reduces the flexibility and control over the encryption key

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/kms/latest/developerguide/services-secrets-manager.html#asm-encrypt
        