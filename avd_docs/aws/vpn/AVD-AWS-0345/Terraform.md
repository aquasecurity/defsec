
Enable VPN login banner options

```hcl
resource "aws_ec2_client_vpn_endpoint" "good_example" {
    client_login_banner_options = "demo-configuration"
}
 
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ec2_client_vpn_endpoint#client_login_banner_options

