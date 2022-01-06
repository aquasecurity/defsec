---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block#bucket"
---

Define a aws_s3_bucket_public_access_block for the given bucket to control public access policies

```hcl
resource "aws_s3_bucket" "example" {
 	bucket = "example"
 	acl = "private-read"
 }
   
 resource "aws_s3_bucket_public_access_block" "example" {
 	bucket = aws_s3_bucket.example.id
 	block_public_acls   = true
 	block_public_policy = true
 }
```
