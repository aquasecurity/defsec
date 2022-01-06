---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_task_definition"
---

Use secrets for the task definition

```hcl
resource "aws_ecs_task_definition" "good_example" {
   container_definitions = <<EOF
 [
   {
     "name": "my_service",
     "essential": true,
     "memory": 256,
     "environment": [
       { "name": "ENVIRONMENT", "value": "development" }
     ]
   }
 ]
 EOF
 
 }
```
