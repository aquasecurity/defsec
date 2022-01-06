---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_folder_iam"
---

Provide access at the service-level instead of folder-level, if required

```hcl
resource "google_folder_iam_binding" "folder-123" {
 	folder = "folder-123"
 	role    = "roles/nothingInParticular"
 }
```
