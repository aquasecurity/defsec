
Set a more restrictive cidr range

```hcl
 resource "nifcloud_security_group_rule" "good_example" {
 	type    = "IN"
 	cidr_ip = "10.0.0.0/16"
 }
 
```
```hcl
resource "nifcloud_security_group_rule" "allow_partner_rsync" {
  type                 = "IN"
  security_group_names = [nifcloud_security_group.….group_name]
  from_port            = 22
  to_port              = 22
  protocol             = "TCP"
  cidr_ip              = "10.0.0.0/16"
}

```

#### Remediation Links
 - https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/security_group_rule#cidr_ip

