
You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms.   
Security groups are a stateful packet filter that controls ingress and egress traffic in a VPC.                                                    
                                                                              
CIS recommends that you create a metric filter and alarm for changes to security groups. Monitoring these changes helps ensure that resources and services aren't unintentionally exposed.

### Impact
Security groups control the ingress and egress, changes could be made to maliciously allow egress of data or external ingress. Without alerting, this could go unnoticed.

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudwatch-alarms-for-cloudtrail.html


