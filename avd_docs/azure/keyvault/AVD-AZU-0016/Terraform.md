---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault#purge_protection_enabled"
---

Enable purge protection for key vaults

```hcl
resource "azurerm_key_vault" "good_example" {
     name                        = "examplekeyvault"
     location                    = azurerm_resource_group.good_example.location
     enabled_for_disk_encryption = true
     soft_delete_retention_days  = 7
     purge_protection_enabled    = true
 }
```
