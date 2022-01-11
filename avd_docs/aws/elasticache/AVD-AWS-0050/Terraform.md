
Configure snapshot retention for redis cluster

```hcl
resource "aws_elasticache_cluster" "good_example" {
  cluster_id           = "cluster-example"
  engine               = "redis"
  node_type            = "cache.m4.large"
  num_cache_nodes      = 1
  parameter_group_name = "default.redis3.2"
  engine_version       = "3.2.10"
  port                 = 6379
  
  snapshot_retention_limit = 5
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticache_cluster#snapshot_retention_limit
        