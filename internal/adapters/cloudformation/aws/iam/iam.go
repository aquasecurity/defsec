package iam

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) iam.IAM {
	return iam.IAM{
		PasswordPolicy: iam.PasswordPolicy{
			Metadata:             types2.NewUnmanagedMetadata(),
			ReusePreventionCount: types2.IntDefault(0, types2.NewUnmanagedMetadata()),
			RequireLowercase:     types2.BoolDefault(false, types2.NewUnmanagedMetadata()),
			RequireUppercase:     types2.BoolDefault(false, types2.NewUnmanagedMetadata()),
			RequireNumbers:       types2.BoolDefault(false, types2.NewUnmanagedMetadata()),
			RequireSymbols:       types2.BoolDefault(false, types2.NewUnmanagedMetadata()),
			MaxAgeDays:           types2.IntDefault(0, types2.NewUnmanagedMetadata()),
			MinimumLength:        types2.IntDefault(0, types2.NewUnmanagedMetadata()),
		},
		Policies: getPolicies(cfFile),
		Groups:   getGroups(cfFile),
		Users:    getUsers(cfFile),
		Roles:    getRoles(cfFile),
	}
}
