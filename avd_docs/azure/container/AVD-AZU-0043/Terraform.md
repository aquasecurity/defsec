---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster#network_policy"
---

Configure a network policy

```hcl
resource "azurerm_kubernetes_cluster" "good_example" {
 	network_profile {
 	  network_policy = "calico"
 	  }
 }
```
