---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_account_password_policy"
---

Limit the password duration with an expiry in the policy

```hcl
resource "aws_iam_account_password_policy" "good_example" {
	max_password_age = 90
}
```
