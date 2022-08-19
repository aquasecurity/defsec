package branch_protections

var terraformRequireSignedCommitsGoodExamples = []string{
	`
 resource "github_branch_protection" "good_example" {
   repository_id = "example"
   pattern       = "main"

   require_signed_commits = true
 }
 `,
}

var terraformRequireSignedCommitsBadExamples = []string{
	`
 resource "github_branch_protection" "good_example" {
   repository_id = "example"
   pattern       = "main"

   require_signed_commits = false
 }
 `,
}

var terraformRequireSignedCommitsLinks = []string{
	`https://registry.terraform.io/providers/integrations/github/latest/docs/resources/branch_protection`,
}

var terraformRequireSignedCommitsRemediationMarkdown = ``
