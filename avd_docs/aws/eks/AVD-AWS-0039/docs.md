
### EKS should have the encryption of secrets enabled

EKS cluster resources should have the encryption_config block set with protection of the secrets resource.

### Impact
EKS secrets could be read if compromised

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://aws.amazon.com/about-aws/whats-new/2020/03/amazon-eks-adds-envelope-encryption-for-secrets-with-aws-kms/
        