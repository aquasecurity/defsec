
Set a more restrictive cidr range

```hcl
resource "aws_network_acl_rule" "good_example" {
  egress         = false
  protocol       = "tcp"
  from_port      = 22
  to_port        = 22
  rule_action    = "allow"
  cidr_block     = "10.0.0.0/16"
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/network_acl_rule#cidr_block
        