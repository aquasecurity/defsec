---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document"
---

Specify the exact permissions required, and to which resources they should apply instead of using wildcards.

```hcl
resource "aws_iam_role_policy" "test_policy" {
 	name = "test_policy"
 	role = aws_iam_role.test_role.id
 
 	policy = data.aws_iam_policy_document.s3_policy.json
 }
 
 resource "aws_iam_role" "test_role" {
 	name = "test_role"
 	assume_role_policy = jsonencode({
 		Version = "2012-10-17"
 		Statement = [
 		{
 			Action = "sts:AssumeRole"
 			Effect = "Allow"
 			Sid    = ""
 			Principal = {
 			Service = "s3.amazonaws.com"
 			}
 		},
 		]
 	})
 }
 
 data "aws_iam_policy_document" "s3_policy" {
   statement {
     principals {
       type        = "AWS"
       identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
     }
     actions   = ["s3:GetObject"]
     resources = [aws_s3_bucket.example.arn]
   }
 }
```
