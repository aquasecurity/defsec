
Enable versioning to protect against accidental/malicious removal or modification

```hcl
resource "aws_s3_bucket" "good_example" {
  
  versioning {
    enabled = true
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket#versioning
        