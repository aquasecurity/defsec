
### Ensure that Cloud Storage bucket is not anonymously or publicly accessible.

Using 'allUsers' or 'allAuthenticatedUsers' as members in an IAM member/binding causes data to be exposed outside of the organisation.

### Default Severity
{{ severity "HIGH" }}

### Impact
Public exposure of sensitive data.

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://jbrojbrojbro.medium.com/you-make-the-rules-with-authentication-controls-for-cloud-storage-53c32543747b
        