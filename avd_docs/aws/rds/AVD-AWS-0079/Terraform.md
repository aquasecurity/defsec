---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/rds_cluster"
---

Enable encryption for RDS clusters

```hcl
resource "aws_rds_cluster" "good_example" {
   name              = "bar"
   kms_key_id  = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
   storage_encrypted = true
 }
```
