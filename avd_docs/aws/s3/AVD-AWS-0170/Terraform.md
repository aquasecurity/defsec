
Enable MFA deletion protection on the bucket

```hcl
resource "aws_s3_bucket" "example" {
	bucket = "bucket"
}

resource "aws_s3_bucket_versioning" "good_example" {
 	bucket = aws_s3_bucket.example.id
   
	versioning_configuration {
		status = "Enabled"
		mfa_delete = "Enabled"
	}
}
 
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_versioning

