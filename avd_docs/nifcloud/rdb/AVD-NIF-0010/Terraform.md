
Use private LAN

```hcl
 resource "nifcloud_db_instance" "good_example" {
   network_id = nifcloud_private_lan.main.id
 }
 
```

#### Remediation Links
 - https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/db_instance#network_id

