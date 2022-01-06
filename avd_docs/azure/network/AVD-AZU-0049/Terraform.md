---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_watcher_flow_log#retention_policy"
---

Ensure flow log retention is turned on with an expiry of >90 days

```hcl
resource "azurerm_network_watcher_flow_log" "good_watcher" {
	network_watcher_name = "good_watcher"
	resource_group_name = "resource-group"

	network_security_group_id = azurerm_network_security_group.test.id
	storage_account_id = azurerm_storage_account.test.id
	enabled = true

	retention_policy {
		enabled = true
		days = 90
	}
}
```
