
### RDP access should not be accessible from the Internet, should be blocked on port 3389

RDP access can be configured on either the network security group or in the network security group rule.

RDP access should not be permitted from the internet (*, 0.0.0.0, /0, internet, any). Consider using the Azure Bastion Service.

### Default Severity
{{ severity "CRITICAL" }}

### Impact
Anyone from the internet can potentially RDP onto an instance

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.microsoft.com/en-us/azure/bastion/tutorial-create-host-portal
        