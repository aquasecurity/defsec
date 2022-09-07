
Enable WAF for the CloudFront distribution

```hcl
 resource "aws_cloudfront_distribution" "good_example" {
 
   origin {
     domain_name = aws_s3_bucket.primary.bucket_regional_domain_name
     origin_id   = "primaryS3"
 
     s3_origin_config {
       origin_access_identity = aws_cloudfront_origin_access_identity.default.cloudfront_access_identity_path
     }
   }
 
   origin {
     domain_name = aws_s3_bucket.failover.bucket_regional_domain_name
     origin_id   = "failoverS3"
 
     s3_origin_config {
       origin_access_identity = aws_cloudfront_origin_access_identity.default.cloudfront_access_identity_path
     }
   }
 
   default_cache_behavior {
     target_origin_id = "groupS3"
   }
 
   web_acl_id = "waf_id"
 }
 
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudfront_distribution#web_acl_id

