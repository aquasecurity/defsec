
### An ingress Network ACL rule allows specific ports from /0.

Opening up ACLs to the public internet is potentially dangerous. You should restrict access to IP addresses or ranges that explicitly require it where possible.

### Default Severity
{{ severity "CRITICAL" }}

### Impact
The ports are exposed for ingressing data to the internet

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html
        