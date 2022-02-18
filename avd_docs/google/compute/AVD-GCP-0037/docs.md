
Sensitive values such as raw encryption keys should not be included in your Terraform code, and should be stored securely by a secrets manager.

### Impact
The encryption key should be considered compromised as it is not stored securely.

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://cloud.google.com/compute/docs/disks/customer-supplied-encryption
        