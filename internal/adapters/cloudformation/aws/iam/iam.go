package iam

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) iam.IAM {
	return iam.IAM{
		PasswordPolicy: iam.PasswordPolicy{
			Metadata:             defsecTypes.NewUnmanagedMetadata(),
			ReusePreventionCount: defsecTypes.IntDefault(0, defsecTypes.NewUnmanagedMetadata()),
			RequireLowercase:     defsecTypes.BoolDefault(false, defsecTypes.NewUnmanagedMetadata()),
			RequireUppercase:     defsecTypes.BoolDefault(false, defsecTypes.NewUnmanagedMetadata()),
			RequireNumbers:       defsecTypes.BoolDefault(false, defsecTypes.NewUnmanagedMetadata()),
			RequireSymbols:       defsecTypes.BoolDefault(false, defsecTypes.NewUnmanagedMetadata()),
			ExpirePasswords:      defsecTypes.BoolDefault(false, defsecTypes.NewUnmanagedMetadata()),
			MaxAgeDays:           defsecTypes.IntDefault(0, defsecTypes.NewUnmanagedMetadata()),
			MinimumLength:        defsecTypes.IntDefault(0, defsecTypes.NewUnmanagedMetadata()),
		},
		Policies: getPolicies(cfFile),
		Groups:   getGroups(cfFile),
		Users:    getUsers(cfFile),
		Roles:    getRoles(cfFile),
	}
}
