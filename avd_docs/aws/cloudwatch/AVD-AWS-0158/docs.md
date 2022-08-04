
You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms.   
Network gateways are required to send and receive traffic to a destination outside a VPC.                                                              
                                                                            
CIS recommends that you create a metric filter and alarm for changes to network gateways. Monitoring these changes helps ensure that all ingress and egress traffic traverses the VPC border via a controlled path.

### Impact
Network gateways control the ingress and egress, changes could be made to maliciously allow egress of data or external ingress. Without alerting, this could go unnoticed.

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudwatch-alarms-for-cloudtrail.html


