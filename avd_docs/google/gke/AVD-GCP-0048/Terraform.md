---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#metadata"
---

Disable legacy metadata endpoints

```hcl
resource "google_container_cluster" "good_example" {
 	metadata {
     disable-legacy-endpoints = true
   }
 }
```
