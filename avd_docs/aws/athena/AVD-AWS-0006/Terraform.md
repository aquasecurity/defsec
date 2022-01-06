---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/athena_workgroup#encryption_configuration"
  - "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/athena_database#encryption_configuration"
---

Enable encryption at rest for Athena databases and workgroup configurations

```hcl
resource "aws_athena_database" "good_example" {
   name   = "database_name"
   bucket = aws_s3_bucket.hoge.bucket
 
   encryption_configuration {
      encryption_option = "SSE_KMS"
      kms_key_arn       = aws_kms_key.example.arn
  }
 }
 
 resource "aws_athena_workgroup" "good_example" {
   name = "example"
 
   configuration {
     enforce_workgroup_configuration    = true
     publish_cloudwatch_metrics_enabled = true
 
     result_configuration {
       output_location = "s3://${aws_s3_bucket.example.bucket}/output/"
 
       encryption_configuration {
         encryption_option = "SSE_KMS"
         kms_key_arn       = aws_kms_key.example.arn
       }
     }
   }
 }
```
