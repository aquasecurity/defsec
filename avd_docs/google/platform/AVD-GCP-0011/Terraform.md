---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_project_iam"
---

Provide access at the service-level instead of project-level, if required

```hcl
resource "google_project_iam_binding" "project-123" {
 	project = "project-123"
 	role    = "roles/nothingInParticular"
 }
```
