
Turn on encryption for all block devices

```hcl
resource "aws_launch_configuration" "good_example" {
  root_block_device {
    encrypted = true
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#ebs-ephemeral-and-root-block-devices
        