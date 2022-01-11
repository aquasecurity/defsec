
Enable encryption for EFS

```hcl
resource "aws_efs_file_system" "good_example" {
  name       = "bar"
  encrypted  = true
  kms_key_id = "my_kms_key"
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/efs_file_system
        