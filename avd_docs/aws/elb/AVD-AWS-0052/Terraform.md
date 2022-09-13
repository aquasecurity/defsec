
Set drop_invalid_header_fields to true

```hcl
 resource "aws_alb" "good_example" {
 	name               = "good_alb"
 	internal           = false
 	load_balancer_type = "application"
 	
 	access_logs {
 	  bucket  = aws_s3_bucket.lb_logs.bucket
 	  prefix  = "test-lb"
 	  enabled = true
 	}
   
 	drop_invalid_header_fields = true
   }
 
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb#drop_invalid_header_fields

