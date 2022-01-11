
### Legacy client authentication methods utilized.

It is recommended to use Service Accounts and OAuth as authentication methods for accessing the master in the container cluster. 

Basic authentication should be disabled by explicitly unsetting the <code>username</code> and <code>password</code> on the <code>master_auth</code> block.

### Default Severity
{{ severity "HIGH" }}

### Impact
Username/password or certificate authentication methods are less secure

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#restrict_authn_methods
        