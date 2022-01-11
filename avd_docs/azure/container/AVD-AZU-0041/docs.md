
### Ensure AKS has an API Server Authorized IP Ranges enabled

The API server is the central way to interact with and manage a cluster. To improve cluster security and minimize attacks, the API server should only be accessible from a limited set of IP address ranges.

### Default Severity
{{ severity "CRITICAL" }}

### Impact
Any IP can interact with the API server

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.microsoft.com/en-us/azure/aks/api-server-authorized-ip-ranges
        