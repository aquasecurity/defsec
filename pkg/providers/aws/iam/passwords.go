package iam

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type PasswordPolicy struct {
	Metadata             defsecTypes.Metadata
	ReusePreventionCount defsecTypes.IntValue
	RequireLowercase     defsecTypes.BoolValue
	RequireUppercase     defsecTypes.BoolValue
	RequireNumbers       defsecTypes.BoolValue
	RequireSymbols       defsecTypes.BoolValue
	ExpirePasswords      defsecTypes.BoolValue
	MaxAgeDays           defsecTypes.IntValue
	MinimumLength        defsecTypes.IntValue
}
