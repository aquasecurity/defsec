---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group"
---

Set a more restrictive cidr range

```hcl
resource "aws_security_group" "good_example" {
 	egress {
 		cidr_blocks = ["1.2.3.4/32"]
 	}
 }
```
