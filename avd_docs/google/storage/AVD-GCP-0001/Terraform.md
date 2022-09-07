
Restrict public access to the bucket.

```hcl
 resource "google_storage_bucket_iam_binding" "binding" {
 	bucket = google_storage_bucket.default.name
 	role = "roles/storage.admin"
 	members = [
 		"user:jane@example.com",
 	]
 }
 			
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/storage_bucket_iam#member/members

