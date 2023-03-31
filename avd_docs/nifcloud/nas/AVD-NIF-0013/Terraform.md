
Use private LAN

```hcl
 resource "nifcloud_nas_instance" "good_example" {
   network_id = nifcloud_private_lan.main.id
 }
 
```

#### Remediation Links
 - https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/nas_instance#network_id

