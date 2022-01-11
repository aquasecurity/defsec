
### Ensure that the expiration date is set on all keys

Expiration Date is an optional Key Vault Key behavior and is not set by default.

Set when the resource will be become inactive.

### Default Severity
{{ severity "MEDIUM" }}

### Impact
Long life keys increase the attack surface when compromised

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.microsoft.com/en-us/powershell/module/az.keyvault/update-azkeyvaultkey?view=azps-5.8.0#example-1--modify-a-key-to-enable-it--and-set-the-expiration-date-and-tags
        