
SQS Policy actions should always be restricted to a specific set.

This ensures that the queue itself cannot be modified or deleted, and prevents possible future additions to queue actions to be implicitly allowed.

### Impact
SQS policies with wildcard actions allow more that is required

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-security-best-practices.html


