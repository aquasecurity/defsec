
Don't use canned ACLs or switch to private acl

```hcl
resource "aws_s3_bucket" "good_example" {
	acl = "private"
}

```
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "yournamehere"
}

resource "aws_s3_bucket_acl" "example" {
  bucket = aws_s3_bucket.example.id
  acl    = "private"
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket

