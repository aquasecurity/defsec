
Set conditions on this provider, for example by restricting it to only be allowed from repositories in your GitHub organization

```hcl
  resource "google_iam_workload_identity_pool" "github" {
    provider = google
    project  = data.google_project.project.project_id
    workload_identity_pool_id = "github"
  }
  
  resource "google_iam_workload_identity_pool_provider" "github" {
    provider = google
    project  = data.google_project.project.project_id
    workload_identity_pool_id          = google_iam_workload_identity_pool.github-actions[0].workload_identity_pool_id
    workload_identity_pool_provider_id = "github"
  
    attribute_condition = "assertion.repository_owner=='your-github-organization'"

    attribute_mapping = {
      "google.subject"       = "assertion.sub"
      "attribute.actor"      = "assertion.actor"
      "attribute.aud"        = "assertion.aud"
      "attribute.repository" = "assertion.repository"
    }
  
    oidc {
      issuer_uri = "https://token.actions.githubusercontent.com"
    }
  }
 
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/iam_workload_identity_pool_provider#attribute_condition

