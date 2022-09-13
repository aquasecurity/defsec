
Set a retention period that will allow for delayed investigation

```hcl
 resource "azurerm_monitor_log_profile" "good_example" {
   name = "good_example"
 
   retention_policy {
     enabled = true
     days    = 365
   }
 }
 
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_log_profile#retention_policy

