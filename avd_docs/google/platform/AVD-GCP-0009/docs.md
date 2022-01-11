
### Users should not be granted service account access at the organization level

Users with service account access at organization level can impersonate any service account. Instead, they should be given access to particular service accounts as required.

### Default Severity
{{ severity "MEDIUM" }}

### Impact
Privilege escalation, impersonation of any/all services

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://cloud.google.com/iam/docs/impersonating-service-accounts
        