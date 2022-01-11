
### SSH access should not be accessible from the Internet, should be blocked on port 22

SSH access can be configured on either the network security group or in the network security group rule. 

SSH access should not be permitted from the internet (*, 0.0.0.0, /0, internet, any)

### Default Severity
{{ severity "CRITICAL" }}

### Impact
Its dangerous to allow SSH access from the internet

<!-- DO NOT CHANGE -->
{{ remediationActions }}

