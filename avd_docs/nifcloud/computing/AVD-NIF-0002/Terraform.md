
Add descriptions for all security groups

```hcl
 resource "nifcloud_security_group" "good_example" {
   group_name  = "http"
   description = "Allow inbound HTTP traffic"
 }
 
```

#### Remediation Links
 - https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/security_group#description

