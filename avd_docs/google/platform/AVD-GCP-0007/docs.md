
### Service accounts should not have roles assigned with excessive privileges

Service accounts should have a minimal set of permissions assigned in order to do their job. They should never have excessive access as if compromised, an attacker can escalate privileges and take over the entire account.

### Default Severity
{{ severity "HIGH" }}

### Impact
Cloud account takeover if a resource using a service account is compromised

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://cloud.google.com/iam/docs/understanding-roles
        