package iamidentitycenter

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/iamidentitycenter"
	"github.com/aquasecurity/defsec/pkg/terraform"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

func Adapt(modules terraform.Modules) iamidentitycenter.IAMIdentityCenter {
	return iamidentitycenter.IAMIdentityCenter{
		PermissionSets: adaptPermissionSets(modules),
	}
}

func adaptPermissionSets(modules terraform.Modules) []iamidentitycenter.PermissionSet {
	var permissionSets []iamidentitycenter.PermissionSet
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_ssoadmin_permission_set") {
			permissionSets = append(permissionSets, adaptPermissionSet(resource))
		}
	}
	return permissionSets
}

func adaptPermissionSet(resource *terraform.Block) iamidentitycenter.PermissionSet {
	permissionSet := iamidentitycenter.PermissionSet{
		Metadata:        resource.GetMetadata(),
		SessionDuration: defsecTypes.StringDefault("", resource.GetMetadata()),
	}

	sessionDuration := resource.GetAttribute("session_duration")
	permissionSet.SessionDuration = sessionDuration.AsStringValueOrDefault("", resource)

	return permissionSet
}
