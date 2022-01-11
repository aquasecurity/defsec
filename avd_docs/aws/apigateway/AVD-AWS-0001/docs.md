
### API Gateway stages for V1 and V2 should have access logging enabled

API Gateway stages should have access log settings block configured to track all access to a particular stage. This should be applied to both v1 and v2 gateway stages.

### Default Severity
{{ severity "MEDIUM" }}

### Impact
Logging provides vital information about access and usage

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html
        