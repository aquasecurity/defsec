---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_project_metadata#"
---

Enable OS Login at project level

```hcl
resource "google_compute_project_metadata" "default" {
   metadata = {
     enable-oslogin = true
   }
 }
```
