---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance"
---

Enable encryption for RDS instances

```hcl
resource "aws_db_instance" "good_example" {
 	storage_encrypted  = true
 }
```
