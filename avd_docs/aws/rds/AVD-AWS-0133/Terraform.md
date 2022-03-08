
Enable Performance Insights to detect potential problems

```hcl
resource "aws_rds_cluster_instance" "good_example" {
  name = "bar"
  performance_insights_enabled = true
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/rds_cluster_instance#performance_insights_enabled
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance#performance_insights_enabled
        