---
additional_links: 
  - "https://www.terraform.io/docs/providers/azure/r/storage_container.html#properties"
---

Disable public access to storage containers

```hcl
resource "azure_storage_container" "good_example" {
 	name                  = "terraform-container-storage"
 	container_access_type = "blob"
 	
 	properties = {
 		"publicAccess" = "off"
 	}
 }
```
