package repositories

import (
	"github.com/aquasecurity/defsec/parsers/terraform"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/github"
)

func Adapt(modules terraform.Modules) []github.Repository {
	return adaptRepositories(modules)
}

func adaptRepositories(modules terraform.Modules) []github.Repository {
	var repositories []github.Repository
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("github_repository") {
			repositories = append(repositories, adaptRepository(resource))
		}
	}
	return repositories
}

func adaptRepository(resource *terraform.Block) github.Repository {

	repo := github.Repository{
		Metadata: resource.GetMetadata(),
		Public:   types.Bool(true, resource.GetMetadata()),
	}

	privateAttr := resource.GetAttribute("private")
	if privateAttr.IsTrue() {
		repo.Public = types.Bool(false, privateAttr.GetMetadata())
	} else if privateAttr.IsFalse() {
		repo.Public = types.Bool(true, privateAttr.GetMetadata())
	}

	repo.Archived = resource.GetAttribute("archived").AsBoolValueOrDefault(false, resource)
	repo.VulnerabilityAlerts = resource.GetAttribute("vulnerability_alerts").AsBoolValueOrDefault(false, resource)

	// visibility overrides private
	visibilityAttr := resource.GetAttribute("visibility")
	if visibilityAttr.Equals("private") || visibilityAttr.Equals("internal") {
		repo.Public = types.Bool(false, visibilityAttr.GetMetadata())
	} else if visibilityAttr.Equals("public") {
		repo.Public = types.Bool(true, visibilityAttr.GetMetadata())
	}

	return repo
}
