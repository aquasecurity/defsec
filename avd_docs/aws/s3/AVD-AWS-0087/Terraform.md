
Prevent policies that allow public access being PUT

```hcl
resource "aws_s3_bucket" "example" {
  bucket = "mybucket"
}

resource "aws_s3_bucket_public_access_block" "good_example" {
  bucket = aws_s3_bucket.example.id
  block_public_policy = true
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block#block_public_policy
        