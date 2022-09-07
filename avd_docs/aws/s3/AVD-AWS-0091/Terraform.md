
Enable ignoring the application of public ACLs in PUT calls

```hcl
resource "aws_s3_bucket" "example" {
	bucket = "bucket"
}

 resource "aws_s3_bucket_public_access_block" "good_example" {
 	bucket = aws_s3_bucket.example.id
   
 	ignore_public_acls = true
 }
 
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block#ignore_public_acls

