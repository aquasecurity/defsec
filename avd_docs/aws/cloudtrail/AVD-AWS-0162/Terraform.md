
Enable logging to CloudWatch

```hcl
 resource "aws_cloudtrail" "good_example" {
   is_multi_region_trail = true
   cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.example.arn}:*" 

 
   event_selector {
     read_write_type           = "All"
     include_management_events = true
 
     data_resource {
       type = "AWS::S3::Object"
       values = ["${data.aws_s3_bucket.important-bucket.arn}/"]
     }
   }
 }

resource "aws_cloudwatch_log_group" "example" {
  name = "Example"
}
 
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail

