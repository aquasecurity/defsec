
Enable Container Insights

```hcl
resource "aws_ecs_cluster" "good_example" {
  name = "services-cluster"
  
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_cluster#setting
        