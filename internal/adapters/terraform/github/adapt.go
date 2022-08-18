package github

import (
	"github.com/aquasecurity/defsec/internal/adapters/terraform/github/branch_protections"
	"github.com/aquasecurity/defsec/internal/adapters/terraform/github/repositories"
	"github.com/aquasecurity/defsec/internal/adapters/terraform/github/secrets"
	"github.com/aquasecurity/defsec/pkg/providers/github"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) github.GitHub {
	return github.GitHub{
		Repositories:       repositories.Adapt(modules),
		EnvironmentSecrets: secrets.Adapt(modules),
		BranchProtections:  branch_protections.Adapt(modules),
	}
}
