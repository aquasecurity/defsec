
Add a logging block to the resource to enable access logging

```hcl
resource "aws_s3_bucket" "good_example" {
  logging {
    target_bucket = "target-bucket"
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket
        