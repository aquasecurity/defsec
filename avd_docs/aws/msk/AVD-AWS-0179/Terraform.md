
Enable at rest encryption

```hcl
 resource "aws_msk_cluster" "good_example" {
 	encryption_info {
		encryption_at_rest_kms_key_arn = "foo-bar-key"
 	}
 }
 
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/msk_cluster#encryption_info-argument-reference

