
You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms.   
                                                                              
  CIS recommends that you create a metric filter and alarm console logins that  aren't protected by MFA. Monitoring for single-factor console logins increases visibility into accounts that aren't protected by MFA.

### Impact
Not alerting on logins with no MFA allows the risk to go un-notified.

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://aws.amazon.com/iam/features/mfa/


