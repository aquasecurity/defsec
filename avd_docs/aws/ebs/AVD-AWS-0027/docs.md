
### EBS volume encryption should use Customer Managed Keys

Encryption using AWS keys provides protection for your EBS volume. To increase control of the encryption and manage factors like rotation use customer managed keys.

### Default Severity
{{ severity "LOW" }}

### Impact
Using AWS managed keys does not allow for fine grained control

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html
        