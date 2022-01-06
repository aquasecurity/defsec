---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/data_factory#public_network_enabled"
---

Set public access to disabled for Data Factory

```hcl
resource "azurerm_data_factory" "good_example" {
   name                = "example"
   location            = azurerm_resource_group.example.location
   resource_group_name = azurerm_resource_group.example.name
   public_network_enabled = false
 }
```
