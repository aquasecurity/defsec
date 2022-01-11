
Enable RBAC

```hcl
resource "azurerm_kubernetes_cluster" "good_example" {
  role_based_access_control {
    enabled = true
  }
}
```

#### Remediation Links
 - https://www.terraform.io/docs/providers/azurerm/r/kubernetes_cluster.html#role_based_access_control
        