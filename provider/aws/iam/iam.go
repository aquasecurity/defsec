package iam

import "github.com/aquasecurity/defsec/types"

type IAM struct {
	PasswordPolicy PasswordPolicy
	Policies       []Policy
	GroupPolicies  []GroupPolicy
	UserPolicies   []UserPolicy
	RolePolicies   []RolePolicy
}

type Policy struct {
	Document types.StringValue
}

type GroupPolicy struct {
	Document types.StringValue
}

type UserPolicy struct {
	Document types.StringValue
}

type RolePolicy struct {
	Document types.StringValue
}
