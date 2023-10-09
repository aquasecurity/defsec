
Include Global Service Events is a default value for Cloudtrail and it publishes events from global services that are not region specific such as IAM, STS and CloudFront. It is feasible that a rogue actor compromising an AWS account might want to disable this field to remove trace of their actions.

### Impact
Events from global services such as IAM are not being published to the log files

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html#cloudtrail-concepts-global-service-events


