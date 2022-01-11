
Enable logging for AKS

```hcl
resource "azurerm_kubernetes_cluster" "good_example" {
  addon_profile {
    oms_agent {
      enabled = true
    }
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster#oms_agent
        