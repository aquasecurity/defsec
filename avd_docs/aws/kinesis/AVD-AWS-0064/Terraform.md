---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kinesis_stream#encryption_type"
---

Enable in transit encryption

```hcl
resource "aws_kinesis_stream" "good_example" {
 	encryption_type = "KMS"
 	kms_key_id = "my/special/key"
 }
```
