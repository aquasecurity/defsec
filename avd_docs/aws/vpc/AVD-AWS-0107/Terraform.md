---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule#cidr_blocks"
---

Set a more restrictive cidr range

```hcl
resource "aws_security_group_rule" "good_example" {
 	type = "ingress"
 	cidr_blocks = ["10.0.0.0/16"]
 }
```
