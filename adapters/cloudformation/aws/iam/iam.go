package iam

import (
	"github.com/aquasecurity/defsec/provider/aws/iam"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result iam.IAM) {

	result.Policies = getPolicies(cfFile)
	result.Roles = getRoles(cfFile)
	result.Users = getUsers(cfFile)
	result.Groups = getGroups(cfFile)
	return result

}
