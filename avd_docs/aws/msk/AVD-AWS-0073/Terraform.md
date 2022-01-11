
Enable in transit encryption

```hcl
resource "aws_msk_cluster" "good_example" {
  encryption_info {
    encryption_in_transit {
      client_broker = "TLS"
      in_cluster = true
    }
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/msk_cluster#encryption_info-argument-reference
        