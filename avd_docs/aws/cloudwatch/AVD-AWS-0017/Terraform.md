---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group#kms_key_id"
---

Enable CMK encryption of CloudWatch Log Groups

```hcl
resource "aws_cloudwatch_log_group" "good_example" {
 	name = "good_example"
 
 	kms_key_id = aws_kms_key.log_key.arn
 }
```
