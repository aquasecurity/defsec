package authorization

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type Authorization struct {
	RoleDefinitions []RoleDefinition
}

type RoleDefinition struct {
	types2.Metadata
	Permissions      []Permission
	AssignableScopes []types2.StringValue
}

type Permission struct {
	types2.Metadata
	Actions []types2.StringValue
}
