---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/data_lake_store"
---

Enable encryption of data lake storage

```hcl
resource "azurerm_data_lake_store" "good_example" {
 	encryption_state = "Enabled"
 }
```
