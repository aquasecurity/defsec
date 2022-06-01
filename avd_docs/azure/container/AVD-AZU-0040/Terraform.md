
Enable logging for AKS

For AzureRM provider 2.x

```hcl
resource "azurerm_kubernetes_cluster" "good_example" {
  addon_profile {
    oms_agent {
      enabled = true
    }
  }
}
```

Alternatively, in AzureRM provider 3.x

```hcl

resource "azurerm_log_analytics_workspace" "example" {
  name                = "acctest-01"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
}

resource "azurerm_kubernetes_cluster" "good_example" {
   oms_agent {
     log_analytics_workspace_id = azurerm_log_analytics_workspace.example.id
   }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster#oms_agent
        