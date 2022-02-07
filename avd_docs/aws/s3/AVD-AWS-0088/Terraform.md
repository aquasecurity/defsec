
Configure bucket encryption

```hcl
resource "aws_kms_key" "good_example" {
  enable_key_rotation = true
}

resource "aws_s3_bucket" "good_example" {
   bucket = "mybucket"
 
   server_side_encryption_configuration {
     rule {
       apply_server_side_encryption_by_default {
         kms_master_key_id = aws_kms_key.example.arn
         sse_algorithm     = "aws:kms"
       }
     }
   }
 }
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket#enable-default-server-side-encryption
        