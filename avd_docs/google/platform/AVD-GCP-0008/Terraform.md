---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_organization_iam"
  - ""
---

Use specialised service accounts for specific purposes.

```hcl
resource "google_service_account" "test" {
 	account_id   = "account123"
 	display_name = "account123"
 }
 			  
 resource "google_organization_iam_member" "org-123" {
 	org_id = "org-123"
 	role    = "roles/whatever"
 	member  = "serviceAccount:${google_service_account.test.email}"
 }
```
