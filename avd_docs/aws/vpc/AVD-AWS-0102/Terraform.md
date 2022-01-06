---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/network_acl_rule#to_port"
---

Set specific allowed ports

```hcl
resource "aws_network_acl_rule" "good_example" {
   egress         = false
   protocol       = "tcp"
   from_port      = 22
   to_port        = 22
   rule_action    = "allow"
   cidr_block     = "0.0.0.0/0"
 }
```
