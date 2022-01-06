---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_account_password_policy"
---

Enforce longer, more complex passwords in the policy

```hcl
resource "aws_iam_account_password_policy" "good_example" {
 	# ...
 	require_uppercase_characters = true
 	# ...
 }
```
