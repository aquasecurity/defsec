
Prevent password reuse in the policy

```hcl
resource "aws_iam_account_password_policy" "good_example" {
  # ...
  password_reuse_prevention = 5
  # ...
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_account_password_policy
        