
### CloudFront distribution does not have a WAF in front.

You should configure a Web Application Firewall in front of your CloudFront distribution. This will mitigate many types of attacks on your web application.

### Default Severity
{{ severity "HIGH" }}

### Impact
Complex web application attacks can more easily be performed without a WAF

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/waf/latest/developerguide/cloudfront-features.html
        