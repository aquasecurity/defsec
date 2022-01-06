---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault_secret#content_type"
---

Provide content type for secrets to aid interpretation on retrieval

```hcl
resource "azurerm_key_vault_secret" "good_example" {
   name         = "secret-sauce"
   value        = "szechuan"
   key_vault_id = azurerm_key_vault.example.id
   content_type = "password"
 }
```
