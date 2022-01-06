---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic#example-with-server-side-encryption-sse"
---

Turn on SNS Topic encryption

```hcl
resource "aws_sns_topic" "good_example" {
 	kms_master_key_id = "/blah"
 }
```
