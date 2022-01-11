
Only allow HTTPS for CloudFront distribution communication

```hcl
resource "aws_cloudfront_distribution" "good_example" {
  default_cache_behavior {
    viewer_protocol_policy = "redirect-to-https"
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudfront_distribution#viewer_protocol_policy
        