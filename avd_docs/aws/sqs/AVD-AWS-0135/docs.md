
Queues should be encrypted with customer managed KMS keys and not default AWS managed keys, in order to allow granular control over access to specific queues.

### Impact
The SQS queue messages could be read if compromised. Key management is very limited when using default keys.

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html


