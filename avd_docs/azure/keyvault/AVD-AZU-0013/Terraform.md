
Set a network ACL for the key vault

```hcl
resource "azurerm_key_vault" "good_example" {
  name                        = "examplekeyvault"
  location                    = azurerm_resource_group.good_example.location
  enabled_for_disk_encryption = true
  soft_delete_retention_days  = 7
  purge_protection_enabled    = false
  
  network_acls {
    bypass = "AzureServices"
    default_action = "Deny"
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault#network_acls
        