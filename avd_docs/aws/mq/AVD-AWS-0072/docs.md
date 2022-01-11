
### Ensure MQ Broker is not publicly exposed

Public access of the MQ broker should be disabled and only allow routes to applications that require access.

### Default Severity
{{ severity "HIGH" }}

### Impact
Publicly accessible MQ Broker may be vulnerable to compromise

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/using-amazon-mq-securely.html#prefer-brokers-without-public-accessibility
        