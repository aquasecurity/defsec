
Add security group for all instances

```hcl
 resource "nifcloud_instance" "good_example" {
   image_id        = data.nifcloud_image.ubuntu.id
   security_group  = nifcloud_security_group.example.group_name

   network_interface {
     network_id = "net-COMMON_GLOBAL"
   }
 }
 
```

#### Remediation Links
 - https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/instance#security_group

