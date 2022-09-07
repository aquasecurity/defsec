
Disable automatic default network creation

```hcl
 resource "google_project" "good_example" {
   name       = "My Project"
   project_id = "your-project-id"
   org_id     = "1234567"
   auto_create_network = false
 }
 
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_project#auto_create_network

