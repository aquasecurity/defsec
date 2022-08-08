
You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms.   
You can have more than one VPC in an account, and you can create a peer connection between two VPCs, enabling network traffic to route between VPCs.
                                                                              
CIS recommends that you create a metric filter and alarm for changes to VPCs. Monitoring these changes helps ensure that authentication and authorization controls remain intact.  

### Impact
Route tables control the flow of network traffic, changes could be made to maliciously allow egress of data or external ingress. Without alerting, this could go unnoticed.

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudwatch-alarms-for-cloudtrail.html


