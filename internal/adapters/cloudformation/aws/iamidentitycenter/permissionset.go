package iamidentitycenter

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/iamidentitycenter"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func getPermissionSets(ctx parser.FileContext) (permissionsets []iamidentitycenter.PermissionSet) {
	for _, r := range ctx.GetResourcesByType("AWS::SSO::PermissionSet") {

		permissionset := iamidentitycenter.PermissionSet{
			Metadata:        r.Metadata(),
			SessionDuration: r.GetStringProperty("SessionDuration"),
		}
		permissionsets = append(permissionsets, permissionset)
	}
	return permissionsets
}
