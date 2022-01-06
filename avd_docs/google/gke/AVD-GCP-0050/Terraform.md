---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#service_account"
---

Use limited permissions for service accounts to be effective

```hcl
resource "google_container_cluster" "good_example" {
 	node_config {
 		service_account = "cool-service-account@example.com"
 	}
 }
```
