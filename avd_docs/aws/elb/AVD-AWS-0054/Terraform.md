---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_listener"
---

Switch to HTTPS to benefit from TLS security features

```hcl
resource "aws_alb_listener" "good_example" {
 	protocol = "HTTPS"
 }
```
