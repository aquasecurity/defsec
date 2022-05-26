Local-disk encryption for emr security configuration

```hcl
resource "aws_emr_security_configuration" "foo" {
  name = "emrsc_other"

  configuration = <<EOF
{
  "EncryptionConfiguration": {
    "AtRestEncryptionConfiguration": {
      "S3EncryptionConfiguration": {
        "EncryptionMode": "SSE-S3"
      },
      "LocalDiskEncryptionConfiguration": {
        "EncryptionKeyProviderType": "AwsKms",
        "AwsKmsKey": "arn:aws:kms:us-west-2:187416307283:alias/tf_emr_test_key"
      }
    },
    "EnableInTransitEncryption": true,
    "EnableAtRestEncryption": true
  }
}
EOF
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/emr_security_configuration
        