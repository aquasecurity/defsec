
Encrypt SQS Queue with a customer-managed key

```hcl
 resource "aws_sqs_queue" "good_example" {
 	kms_master_key_id = "/blah"
 }
 
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sqs_queue#server-side-encryption-sse

