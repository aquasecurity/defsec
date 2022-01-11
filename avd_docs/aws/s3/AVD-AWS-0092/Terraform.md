
Add a logging block to the resource to enable access logging

```hcl
resource "aws_s3_bucket" "good_example" {
  acl = "private"
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket
        