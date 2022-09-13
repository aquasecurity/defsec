
Enable vulnerability alerts

```hcl
 resource "github_repository" "good_example" {
   name        = "example"
   description = "My awesome codebase"

   vulnerability_alerts = true

   template {
     owner = "github"
     repository = "terraform-module-template"
   }
 }
 
```

#### Remediation Links
 - https://registry.terraform.io/providers/integrations/github/latest/docs/resources/repository

