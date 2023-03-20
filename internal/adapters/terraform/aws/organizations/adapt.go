package organizations

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/organizations"
	"github.com/aquasecurity/defsec/pkg/terraform"
	"github.com/aquasecurity/defsec/pkg/types"
)

func Adapt(modules terraform.Modules) organizations.Organizations {
	return organizations.Organizations{
		Accounts:          adaptAccounts(modules),
		Organization:      adaptOrganization(modules),
		AccountHandshakes: nil,
	}
}

func adaptAccounts(modules terraform.Modules) []organizations.Account {
	var accounts []organizations.Account
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_organizations_account") {
			accounts = append(accounts, organizations.Account{
				Metadata: resource.GetMetadata(),
				Id:       resource.GetAttribute("id").AsStringValueOrDefault("", resource),
			})
		}
	}
	return accounts
}

func adaptOrganization(modules terraform.Modules) organizations.Organization {
	organization := organizations.Organization{
		Metadata:   types.NewUnmanagedMetadata(),
		FeatureSet: types.String("", types.NewUnmanagedMetadata()),
	}
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_organizations_organization") {
			organization.Metadata = resource.GetMetadata()
			organization.FeatureSet = types.StringDefault("", resource.GetMetadata())
		}
	}
	return organization
}
