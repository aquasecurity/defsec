
Add descriptions for all security groups rules

```hcl
 resource "nifcloud_security_group_rule" "good_example" {
   type        = "IN"
   description = "HTTP from VPC"
   from_port   = 80
   to_port     = 80
   protocol    = "TCP"
   cidr_ip     = nifcloud_private_lan.main.cidr_block
 }
 
```

#### Remediation Links
 - https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/security_group_rule#description

