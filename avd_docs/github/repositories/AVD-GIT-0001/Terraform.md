---
additional_links: 
  - "https://registry.terraform.io/providers/integrations/github/latest/docs/resources/repository"
---

Make sensitive or commercially important repositories private

```hcl
resource "github_repository" "good_example" {
   name        = "example"
   description = "My awesome codebase"
 
   visibility  = "private"
 
   template {
     owner = "github"
     repository = "terraform-module-template"
   }
 }
```
