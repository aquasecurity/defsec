
Configure KMS key to auto rotate

```hcl
resource "aws_kms_key" "good_example" {
  enable_key_rotation = true
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key#enable_key_rotation
        