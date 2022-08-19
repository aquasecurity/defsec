
GitHub branch protection should be set to require signed commits.

You can do this by setting the <code>require_signed_commits</code> attribute to 'true'.

### Impact
Commits may not be verified and signed as coming from a trusted developer

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://registry.terraform.io/providers/integrations/github/latest/docs/resources/branch_protection#require_signed_commits

- https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification

- https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/defining-the-mergeability-of-pull-requests/about-protected-branches#require-signed-commits


