
Enable versioning to protect against accidental/malicious removal or modification

```hcl
resource "aws_s3_bucket" "good_example" {

	versioning {
		enabled = true
	}
}

```
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "yournamehere"

  # ... other configuration ...
}

resource "aws_s3_bucket_versioning" "example" {
  bucket = aws_s3_bucket.example.id
  versioning_configuration {
    status = "Enabled"
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket#versioning

