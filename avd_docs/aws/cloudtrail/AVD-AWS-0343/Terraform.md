
Enable include global service events for Cloudtrail

```hcl
 resource "aws_cloudtrail" "good_example" {
   include_global_service_events = true
   s3_bucket_name = "abcdefgh"
 }
 
```

#### Remediation Links
 - https://registry.terraform.io/providers/rgeraskin/aws2/latest/docs/resources/cloudtrail#include_global_service_events

