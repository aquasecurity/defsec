
Turn on SQS Queue encryption

```hcl
 resource "aws_sqs_queue" "good_example" {
 	kms_master_key_id = "/blah"
 }
 
```
```hcl
resource "aws_sqs_queue" "terraform_queue" {
   name                    = "terraform-example-queue"
   sqs_managed_sse_enabled = true
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sqs_queue#server-side-encryption-sse

