
### Trusted Microsoft Services should have bypass access to Storage accounts

Some Microsoft services that interact with storage accounts operate from networks that can't be granted access through network rules. 

To help this type of service work as intended, allow the set of trusted Microsoft services to bypass the network rules

### Default Severity
{{ severity "HIGH" }}

### Impact
Trusted Microsoft Services won't be able to access storage account unless rules set to allow

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.microsoft.com/en-us/azure/storage/common/storage-network-security#trusted-microsoft-services
        