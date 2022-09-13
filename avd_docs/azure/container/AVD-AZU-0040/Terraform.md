
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
```hcl
 resource "azurerm_kubernetes_cluster" "good_example" {
 		oms_agent {
			log_analytics_workspace_id = "whatever"
 		}
 }
 
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster#oms_agent

