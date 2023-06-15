
Set conditions on this provider, for example by restricting it to only be allowed from repositories in your GitHub organization.

```hcl
 resource "google_iam_workload_identity_pool_provider" "github" {
    project                            = "example-project"
    workload_identity_pool_id          = "example-pool"
    workload_identity_pool_provider_id = "example-provider"
  
    attribute_condition = "assertion.repository_owner=='your-github-organization'"

    attribute_mapping = {
      "google.subject"       = "assertion.sub"
      "attribute.actor"      = "assertion.actor"
      "attribute.aud"        = "assertion.aud"
      "attribute.repository" = "assertion.repository"
    }
  }		
```

#### Remediation Links

- https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/iam_workload_identity_pool_provider#attribute_condition

