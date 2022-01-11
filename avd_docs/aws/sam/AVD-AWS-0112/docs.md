
### SAM API domain name uses outdated SSL/TLS protocols.

You should not use outdated/insecure TLS versions for encryption. You should be using TLS v1.2+.

### Default Severity
{{ severity "HIGH" }}

### Impact
Outdated SSL policies increase exposure to known vulnerabilities

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-property-api-domainconfiguration.html#sam-api-domainconfiguration-securitypolicy
        