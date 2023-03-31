
Set a more restrictive cidr range

```hcl
 resource "nifcloud_db_security_group" "good_example" {
   rule {
     cidr_ip = "10.0.0.0/16"
   }
 }
 
```

#### Remediation Links
 - https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/db_security_group#cidr_ip

