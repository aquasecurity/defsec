
Add descriptions for all db security groups

```hcl
 resource "nifcloud_db_security_group" "good_example" {
   group_name  = "app"
   description = "Allow from app traffic"
 }
 
```

#### Remediation Links
 - https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/db_security_group#description

