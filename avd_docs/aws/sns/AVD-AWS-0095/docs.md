
### Unencrypted SNS topic.

Queues should be encrypted with customer managed KMS keys and not default AWS managed keys, in order to allow granular control over access to specific queues.

### Default Severity
{{ severity "HIGH" }}

### Impact
The SNS topic messages could be read if compromised

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/sns/latest/dg/sns-server-side-encryption.html
        