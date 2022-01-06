---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#enable_shielded_nodes"
---

Enable node shielding

```hcl
resource "google_container_cluster" "good_example" {
 	enable_shielded_nodes = "true"
 }
```
