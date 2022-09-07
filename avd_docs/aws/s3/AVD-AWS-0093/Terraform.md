
Limit the access to public buckets to only the owner or AWS Services (eg; CloudFront)

```hcl
resource "aws_s3_bucket" "example" {
	bucket = "bucket"
}

resource "aws_s3_bucket_public_access_block" "good_example" {
 	bucket = aws_s3_bucket.example.id
   
 	restrict_public_buckets = true
 }
 
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block#restrict_public_buckets¡

