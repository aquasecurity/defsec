package branch_protections

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckRequireSignedCommits = rules.Register(
	scan.Rule{
		AVDID:      "AVD-GIT-0004",
		Provider:   providers.GitHubProvider,
		Service:    "branch_protections",
		ShortCode:  "require_signed_commits",
		Summary:    "GitHub branch protection does not require signed commits.",
		Impact:     "Commits may not be verified and signed as coming from a trusted developer",
		Resolution: "Require signed commits",
		Explanation: `GitHub branch protection should be set to require signed commits.

You can do this by setting the <code>require_signed_commits</code> attribute to 'true'.`,
		Links: []string{
			"https://registry.terraform.io/providers/integrations/github/latest/docs/resources/branch_protection#require_signed_commits",
			"https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification",
			"https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/defining-the-mergeability-of-pull-requests/about-protected-branches#require-signed-commits",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformRequireSignedCommitsGoodExamples,
			BadExamples:         terraformRequireSignedCommitsBadExamples,
			Links:               terraformRequireSignedCommitsLinks,
			RemediationMarkdown: terraformRequireSignedCommitsRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, branchProtection := range s.GitHub.BranchProtections {
			if branchProtection.RequireSignedCommits.IsFalse() {
				results.Add(
					"Branch protection does not require signed commits,",
					branchProtection.RequireSignedCommits,
				)
			} else {
				results.AddPassed(branchProtection)
			}
		}
		return
	},
)
