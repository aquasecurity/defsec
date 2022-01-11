
Enable at-rest encryption for replication group

```hcl
resource "aws_elasticache_replication_group" "good_example" {
  replication_group_id = "foo"
  replication_group_description = "my foo cluster"
  
  at_rest_encryption_enabled = true
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticache_replication_group#at_rest_encryption_enabled
        