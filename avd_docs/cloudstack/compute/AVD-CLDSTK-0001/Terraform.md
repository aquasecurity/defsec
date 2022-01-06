---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/cloudstack/latest/docs/resources/instance#"
---

Don't use sensitive data in the user data section

```hcl
resource "cloudstack_instance" "web" {
   name             = "server-1"
   service_offering = "small"
   network_id       = "6eb22f91-7454-4107-89f4-36afcdf33021"
   template         = "CentOS 6.5"
   zone             = "zone-1"
   user_data        = <<EOF
 export GREETING="Hello there"
 EOF
 }
```
