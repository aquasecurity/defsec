---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#client_cert_enabled"
---

Enable incoming certificates for clients

```hcl
resource "azurerm_app_service" "good_example" {
   name                = "example-app-service"
   location            = azurerm_resource_group.example.location
   resource_group_name = azurerm_resource_group.example.name
   app_service_plan_id = azurerm_app_service_plan.example.id
   client_cert_enabled = true
 }
```
