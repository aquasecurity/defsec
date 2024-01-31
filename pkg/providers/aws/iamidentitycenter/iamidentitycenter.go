package iamidentitycenter

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type IAMIdentityCenter struct {
	PermissionSets []PermissionSet
}

type PermissionSet struct {
	Metadata        defsecTypes.Metadata
	SessionDuration defsecTypes.StringValue
}
