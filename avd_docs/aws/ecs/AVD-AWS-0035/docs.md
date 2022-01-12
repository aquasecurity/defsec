
### ECS Task Definitions with EFS volumes should use in-transit encryption

ECS task definitions that have volumes using EFS configuration should explicitly enable in transit encryption to prevent the risk of data loss due to interception.

### Impact
Intercepted traffic to and from EFS may lead to data loss

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/AmazonECS/latest/userguide/efs-volumes.html
 - https://docs.aws.amazon.com/efs/latest/ug/encryption-in-transit.html
        