---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/launch_configuration#associate_public_ip_address"
  - "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#associate_public_ip_address"
---

Set the instance to not be publicly accessible

```hcl
resource "aws_launch_configuration" "good_example" {
 	associate_public_ip_address = false
 }
```
