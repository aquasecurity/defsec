---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block#block_public_acls"
---

Enable blocking any PUT calls with a public ACL specified

```hcl
resource "aws_s3_bucket" "good_example" {
  bucket = "mybucket"
}

resource "aws_s3_bucket_public_access_block" "good_example" {
  bucket = aws_s3_bucket.good_example.id
  block_public_acls = true
}
```
