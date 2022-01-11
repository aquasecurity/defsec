
### Ensure all data stored in the launch configuration EBS is securely encrypted

When creating Launch Configurations, user data can be used for the initial configuration of the instance. User data must not contain any sensitive data.

### Default Severity
{{ severity "HIGH" }}

### Impact
Sensitive credentials in user data can be leaked

<!-- DO NOT CHANGE -->
{{ remediationActions }}

