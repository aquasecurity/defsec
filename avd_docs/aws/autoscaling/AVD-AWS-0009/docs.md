
### Launch configuration should not have a public IP address.

You should limit the provision of public IP addresses for resources. Resources should not be exposed on the public internet, but should have access limited to consumers required for the function of your application.

### Impact
The instance or configuration is publicly accessible

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-instance-addressing.html
        