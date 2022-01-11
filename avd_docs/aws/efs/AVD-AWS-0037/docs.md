
### EFS Encryption has not been enabled

If your organization is subject to corporate or regulatory policies that require encryption of data and metadata at rest, we recommend creating a file system that is encrypted at rest, and mounting your file system using encryption of data in transit.

### Default Severity
{{ severity "HIGH" }}

### Impact
Data can be read from the EFS if compromised

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/efs/latest/ug/encryption.html
        