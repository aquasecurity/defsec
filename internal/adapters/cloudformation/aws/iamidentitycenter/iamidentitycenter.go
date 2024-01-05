package iamidentitycenter

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/iamidentitycenter"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) iamidentitycenter.IAMIdentityCenter {
	return iamidentitycenter.IAMIdentityCenter{
		PermissionSets: getPermissionSets(cfFile),
	}
}
