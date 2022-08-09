package iam

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type PasswordPolicy struct {
	types2.Metadata
	ReusePreventionCount types2.IntValue
	RequireLowercase     types2.BoolValue
	RequireUppercase     types2.BoolValue
	RequireNumbers       types2.BoolValue
	RequireSymbols       types2.BoolValue
	MaxAgeDays           types2.IntValue
	MinimumLength        types2.IntValue
}
