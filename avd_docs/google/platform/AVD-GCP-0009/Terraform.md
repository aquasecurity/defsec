---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_organization_iam"
---

Provide access at the service-level instead of organization-level, if required

```hcl
resource "google_organization_iam_binding" "organization-123" {
 	org_id  = "org-123"
 	role    = "roles/nothingInParticular"
 }
```
