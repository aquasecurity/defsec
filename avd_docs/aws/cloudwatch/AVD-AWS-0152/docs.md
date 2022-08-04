
You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms.   
                                                                              
CIS recommends that you create a metric filter and alarm for failed console authentication attempts. Monitoring failed console logins might decrease lead time to detect an attempt to brute-force a credential, which might provide an indicator, such as source IP, that you can use in other event correlations.

### Impact
IAM Policy changes could lead to excessive permissions and may have been performed maliciously.

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://aws.amazon.com/iam/features/mfa/


