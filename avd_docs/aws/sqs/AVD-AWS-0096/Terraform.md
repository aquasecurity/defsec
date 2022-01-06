---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sqs_queue#server-side-encryption-sse"
---

Turn on SQS Queue encryption

```hcl
resource "aws_sqs_queue" "good_example" {
 	kms_master_key_id = "/blah"
 }
```
