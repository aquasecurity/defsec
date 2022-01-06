---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_log_profile#categories"
---

Configure log profile to capture all activities

```hcl
resource "azurerm_monitor_log_profile" "good_example" {
   name = "good_example"
 
   categories = [
 	  "Action",
 	  "Delete",
 	  "Write",
   ]
 
   retention_policy {
     enabled = true
     days    = 365
   }
 }
```
