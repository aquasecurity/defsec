
Disable public access to storage containers

```hcl
 resource "azurerm_storage_container" "good_example" {
 	name                  = "terraform-container-storage"
 	container_access_type = "private"
 }
 
```

#### Remediation Links
 - https://www.terraform.io/docs/providers/azure/r/storage_container.html#properties

