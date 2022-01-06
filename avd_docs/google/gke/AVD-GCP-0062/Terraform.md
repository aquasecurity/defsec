---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#enable_legacy_abac"
---

Switch to using RBAC permissions

```hcl
resource "google_container_cluster" "good_example" {
 	# ...
 	# enable_legacy_abac not set
 	# ...
 }
```
