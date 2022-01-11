
### SAM API must have data cache enabled

Method cache encryption ensures that any sensitive data in the cache is not vulnerable to compromise in the event of interception

### Default Severity
{{ severity "MEDIUM" }}

### Impact
Data stored in the cache that is unencrypted may be vulnerable to compromise

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-apigateway-stage-methodsetting.html#cfn-apigateway-stage-methodsetting-cachedataencrypted
        