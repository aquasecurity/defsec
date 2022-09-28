package authorization

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Authorization struct {
	RoleDefinitions []RoleDefinition
}

type RoleDefinition struct {
	Metadata         defsecTypes.Metadata
	Permissions      []Permission
	AssignableScopes []defsecTypes.StringValue
}

type Permission struct {
	Metadata defsecTypes.Metadata
	Actions  []defsecTypes.StringValue
}
