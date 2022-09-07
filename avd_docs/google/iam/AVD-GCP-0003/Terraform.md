
Roles should be granted permissions and assigned to users

```hcl
 resource "google_project_iam_binding" "good_example" {
 	members = [
 		"group:test@example.com",
 		]
 }
 
 resource "google_storage_bucket_iam_member" "good_example" {
 	member = "serviceAccount:test@example.com"
 }
```

#### Remediation Links
 - https://www.terraform.io/docs/providers/google/d/iam_policy.html#members

