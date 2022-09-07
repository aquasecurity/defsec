
Only allow secure connection for transferring data into storage accounts

```hcl
 resource "azurerm_storage_account" "good_example" {
   name                      = "storageaccountname"
   resource_group_name       = azurerm_resource_group.example.name
   location                  = azurerm_resource_group.example.location
   account_tier              = "Standard"
   account_replication_type  = "GRS"
   enable_https_traffic_only = true
 }
 
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account#enable_https_traffic_only

