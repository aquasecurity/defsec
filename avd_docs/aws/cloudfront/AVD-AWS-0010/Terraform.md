
Enable logging for CloudFront distributions

```hcl
 resource "aws_cloudfront_distribution" "good_example" {
 	// other config
 	logging_config {
 		include_cookies = false
 		bucket          = "mylogs.s3.amazonaws.com"
 		prefix          = "myprefix"
 	}
 }
 
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudfront_distribution#logging_config

