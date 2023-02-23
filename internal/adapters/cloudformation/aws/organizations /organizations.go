package organizations

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/organizations"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func Adapt(cfFile parser.FileContext) organizations.Organizations {
	return organizations.Organizations{
		Accounts: getAccounts(cfFile),
	}
}
