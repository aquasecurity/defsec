---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account#min_tls_version"
---

Use a more recent TLS/SSL policy for the load balancer

```hcl
resource "azurerm_storage_account" "good_example" {
   name                     = "storageaccountname"
   resource_group_name      = azurerm_resource_group.example.name
   location                 = azurerm_resource_group.example.location
   min_tls_version          = "TLS1_2"
 }
```
