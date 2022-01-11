
Keep policy scope to the minimum that is required to be effective

```hcl
resource "aws_sqs_queue_policy" "good_example" {
  queue_url = aws_sqs_queue.q.id
  
  policy = <<POLICY
  {
    "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "sqs:SendMessage"
    }
    ]
  }
  POLICY
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sqs_queue_policy
        