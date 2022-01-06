---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ebs_volume#encrypted"
---

Enable encryption of EBS volumes

```hcl
resource "aws_ebs_volume" "good_example" {
   availability_zone = "us-west-2a"
   size              = 40
 
   tags = {
     Name = "HelloWorld"
   }
   encrypted = true
 }
```
