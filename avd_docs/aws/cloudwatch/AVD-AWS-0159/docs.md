
You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms.     
Routing tables route network traffic between subnets and to network gateways.                                                                   
                                                                              
CIS recommends that you create a metric filter and alarm for changes to route tables. Monitoring these changes helps ensure that all VPC traffic flows through an expected path.

### Impact
Route tables control the flow of network traffic, changes could be made to maliciously allow egress of data or external ingress. Without alerting, this could go unnoticed.

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudwatch-alarms-for-cloudtrail.html


