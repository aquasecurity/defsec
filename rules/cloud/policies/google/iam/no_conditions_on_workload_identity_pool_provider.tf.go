package iam

var terraformNoConditionOnWorkloadIdentityPoolProviderGoodExamples = []string{
	`
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
 `,
}

var terraformNoConditionOnWorkloadIdentityPoolProviderBadExamples = []string{
	`
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
 `,
}

var terraformNoConditionOnWorkloadIdentityPoolProviderLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/iam_workload_identity_pool_provider#attribute_condition`,
}

var terraformNoConditionOnWorkloadIdentityPoolProviderMarkdown = ``
