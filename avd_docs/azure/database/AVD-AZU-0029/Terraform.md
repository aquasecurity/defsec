---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/sql_firewall_rule#end_ip_address"
---

Don't use wide ip ranges for the sql firewall

```hcl
resource "azurerm_sql_firewall_rule" "good_example" {
   name                = "good_rule"
   resource_group_name = azurerm_resource_group.example.name
   server_name         = azurerm_sql_server.example.name
   start_ip_address    = "0.0.0.0"
   end_ip_address      = "0.0.0.0"
 }
```
