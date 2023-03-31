
Add security group for all vpnGateways

```hcl
 resource "nifcloud_vpn_gateway" "good_example" {
   security_group  = nifcloud_security_group.example.group_name

   network_interface {
     network_id = "net-COMMON_GLOBAL"
   }
 }
 
```

#### Remediation Links
 - https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/vpn_gateway#security_group

