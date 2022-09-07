
Add descriptions for all security groups and rules

```hcl
resource "aws_security_group" "bar" {
	name = "security-group"
}

resource "aws_elasticache_security_group" "good_example" {
	name = "elasticache-security-group"
	security_group_names = [aws_security_group.bar.name]
	description = "something"
}
	
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticache_security_group#description

