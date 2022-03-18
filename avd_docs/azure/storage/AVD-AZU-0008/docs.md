
You can configure your storage account to accept requests from secure connections only by setting the Secure transfer required property for the storage account. 

When you require secure transfer, any requests originating from an insecure connection are rejected. 

Microsoft recommends that you always require secure transfer for all of your storage accounts.

### Impact
Insecure transfer of data into secure accounts could be read if intercepted

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.microsoft.com/en-us/azure/storage/common/storage-require-secure-transfer


