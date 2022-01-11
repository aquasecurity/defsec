
### Key vault should have purge protection enabled

Purge protection is an optional Key Vault behavior and is not enabled by default.

Purge protection can only be enabled once soft-delete is enabled. It can be turned on via CLI or PowerShell.

### Default Severity
{{ severity "MEDIUM" }}

### Impact
Keys could be purged from the vault without protection

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview#purge-protection
        