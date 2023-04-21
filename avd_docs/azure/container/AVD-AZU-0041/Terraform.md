
Limit the access to the API server to a limited IP range

```hcl
 resource "azurerm_kubernetes_cluster" "good_example" {
	api_server_access_profile {
		authorized_ip_ranges = [
 		"1.2.3.4/32"
 	]

	}
     
 }
 
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster#api_server_authorized_ip_ranges

