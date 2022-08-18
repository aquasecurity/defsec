
Require signed commits for a repository

```hcl
resource "github_branch_protection" "good_example" {
  repository_id = "example"
  pattern       = "main"

  require_signed_commits = true
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/integrations/github/latest/docs/resources/branch_protection#require_signed_commits
