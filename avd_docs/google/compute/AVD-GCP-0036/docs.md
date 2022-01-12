
### Instances should not override the project setting for OS Login

OS Login automatically revokes the relevant SSH keys when an IAM user has their access revoked.

### Impact
Access via SSH key cannot be revoked automatically when an IAM user is removed.

<!-- DO NOT CHANGE -->
{{ remediationActions }}

