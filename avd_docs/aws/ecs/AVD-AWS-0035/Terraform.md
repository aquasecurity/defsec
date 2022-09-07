
Enable in transit encryption when using efs

```hcl
 resource "aws_ecs_task_definition" "good_example" {
 	family                = "service"
 	container_definitions = file("task-definitions/service.json")
   
 	volume {
 	  name = "service-storage"
   
 	  efs_volume_configuration {
 		file_system_id          = aws_efs_file_system.fs.id
 		root_directory          = "/opt/data"
 		transit_encryption      = "ENABLED"
 		transit_encryption_port = 2999
 		authorization_config {
 		  access_point_id = aws_efs_access_point.test.id
 		  iam             = "ENABLED"
 		}
 	  }
 	}
   }
 
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_task_definition#transit_encryption

