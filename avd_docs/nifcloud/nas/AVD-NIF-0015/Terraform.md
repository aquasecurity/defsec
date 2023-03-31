
Add descriptions for all nas security groups

```hcl
 resource "nifcloud_nas_security_group" "good_example" {
   group_name  = "app"
   description = "Allow from app traffic"
 }
 
```

#### Remediation Links
 - https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/nas_security_group#description

