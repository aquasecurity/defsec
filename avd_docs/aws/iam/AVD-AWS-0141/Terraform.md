
Use lower privileged accounts instead, so only required privileges are available.

```hcl
resource "aws_iam_access_key" "good_example" {
 	user = "lowprivuser"
}
 			
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_access_key

