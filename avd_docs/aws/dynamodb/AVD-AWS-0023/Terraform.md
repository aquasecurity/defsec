
Enable encryption at rest for DAX Cluster

```hcl
resource "aws_dax_cluster" "good_example" {
  // other DAX config
  
  server_side_encryption {
    enabled = true // enabled server side encryption
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/dax_cluster#server_side_encryption
        