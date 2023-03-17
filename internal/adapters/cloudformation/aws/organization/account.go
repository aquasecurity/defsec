package organizations

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/organizations"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func getAccounts(ctx parser.FileContext) []organizations.Account {
	var accounts []organizations.Account

	accountResources := ctx.GetResourcesByType("AWS::Organizations::Account")
	for _, r := range accountResources {
		accounts = append(accounts, organizations.Account{
			Metadata: r.Metadata(),
			Id:       r.GetStringProperty("AccountId"),
		})
	}

	return accounts
}
