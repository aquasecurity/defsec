package organizations

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/organizations"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) organizations.Organizations {
	return organizations.Organizations{
		Accounts: adaptAccount(modules),
	}
}

func adaptAccount(modules terraform.Modules) []organizations.Account {
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
