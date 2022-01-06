---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_folder_iam"
  - ""
---

Use specialised service accounts for specific purposes.

```hcl
resource "google_service_account" "test" {
 	account_id   = "account123"
 	display_name = "account123"
 }
 			  
 resource "google_folder_iam_member" "folder-123" {
 	folder = "folder-123"
 	role    = "roles/whatever"
 	member  = "serviceAccount:${google_service_account.test.email}"
 }
```
