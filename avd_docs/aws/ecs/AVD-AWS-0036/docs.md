
### Task definition defines sensitive environment variable(s).

You should not make secrets available to a user in plaintext in any scenario. Secrets can instead be pulled from a secure secret storage system by the service requiring them.

### Default Severity
{{ severity "CRITICAL" }}

### Impact
Sensitive data could be exposed in the AWS Management Console

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/systems-manager/latest/userguide/integration-ps-secretsmanager.html
 - https://www.vaultproject.io/
        