
### Ensure that Cloud Storage buckets have uniform bucket-level access enabled

When you enable uniform bucket-level access on a bucket, Access Control Lists (ACLs) are disabled, and only bucket-level Identity and Access Management (IAM) permissions grant access to that bucket and the objects it contains. You revoke all access granted by object ACLs and the ability to administrate permissions using bucket ACLs.

### Impact
ACLs are difficult to manage and often lead to incorrect/unintended configurations.

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://cloud.google.com/storage/docs/uniform-bucket-level-access
 - https://jbrojbrojbro.medium.com/you-make-the-rules-with-authentication-controls-for-cloud-storage-53c32543747b
        