
### Lambda functions should have X-Ray tracing enabled

X-Ray tracing enables end-to-end debugging and analysis of all function activity. This will allow for identifying bottlenecks, slow downs and timeouts.

### Default Severity
{{ severity "LOW" }}

### Impact
WIthout full tracing enabled it is difficult to trace the flow of logs

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/lambda/latest/dg/services-xray.html
        