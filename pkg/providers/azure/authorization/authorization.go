package authorization

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Authorization struct {
	RoleDefinitions []RoleDefinition
}

type RoleDefinition struct {
	defsecTypes.Metadata
	Permissions      []Permission
	AssignableScopes []defsecTypes.StringValue
}

type Permission struct {
	defsecTypes.Metadata
	Actions []defsecTypes.StringValue
}
