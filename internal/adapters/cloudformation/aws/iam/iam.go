package iam

import (
	"github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) iam.IAM {
	return iam.IAM{
		PasswordPolicy: iam.PasswordPolicy{
			Metadata:             types.NewUnmanagedMetadata(),
			ReusePreventionCount: types.IntDefault(0, types.NewUnmanagedMetadata()),
			RequireLowercase:     types.BoolDefault(false, types.NewUnmanagedMetadata()),
			RequireUppercase:     types.BoolDefault(false, types.NewUnmanagedMetadata()),
			RequireNumbers:       types.BoolDefault(false, types.NewUnmanagedMetadata()),
			RequireSymbols:       types.BoolDefault(false, types.NewUnmanagedMetadata()),
			MaxAgeDays:           types.IntDefault(0, types.NewUnmanagedMetadata()),
			MinimumLength:        types.IntDefault(0, types.NewUnmanagedMetadata()),
		},
		Policies: getPolicies(cfFile),
		Groups:   getGroups(cfFile),
		Users:    getUsers(cfFile),
		Roles:    getRoles(cfFile),
	}
}
