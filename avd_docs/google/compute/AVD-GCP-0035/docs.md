
### An outbound firewall rule allows traffic to /0.

Network security rules should not use very broad subnets.

Where possible, segments should be broken into smaller subnets and avoid using the <code>/0</code> subnet.

### Impact
The port is exposed for egress to the internet

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://cloud.google.com/vpc/docs/using-firewalls
        