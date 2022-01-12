
### The minimum TLS version for Storage Accounts should be TLS1_2

Azure Storage currently supports three versions of the TLS protocol: 1.0, 1.1, and 1.2. 

Azure Storage uses TLS 1.2 on public HTTPS endpoints, but TLS 1.0 and TLS 1.1 are still supported for backward compatibility.

This check will warn if the minimum TLS is not set to TLS1_2.

### Impact
The TLS version being outdated and has known vulnerabilities

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.microsoft.com/en-us/azure/storage/common/transport-layer-security-configure-minimum-version
        