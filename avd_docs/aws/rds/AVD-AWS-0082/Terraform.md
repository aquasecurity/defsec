---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance"
---

Set the database to not be publicly accessible

```hcl
resource "aws_db_instance" "good_example" {
 	publicly_accessible = false
 }
```
