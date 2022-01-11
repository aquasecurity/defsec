
### Enable disk encryption on managed disk

Manage disks should be encrypted at rest. When specifying the <code>encryption_settings</code> block, the enabled attribute should be set to <code>true</code>.

### Default Severity
{{ severity "HIGH" }}

### Impact
Data could be read if compromised

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.microsoft.com/en-us/azure/virtual-machines/linux/disk-encryption
        