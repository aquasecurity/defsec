
### OS Login should be enabled at project level

OS Login automatically revokes the relevant SSH keys when an IAM user has their access revoked.

### Default Severity
{{ severity "MEDIUM" }}

### Impact
Access via SSH key cannot be revoked automatically when an IAM user is removed.

<!-- DO NOT CHANGE -->
{{ remediationActions }}

