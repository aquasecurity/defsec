package iam

import "github.com/aquasecurity/defsec/types"

type IAM struct {
}

type Member struct {
	types.Metadata
	Member                types.StringValue
	Role                  types.StringValue
	DefaultServiceAccount types.BoolValue
}

type Binding struct {
	types.Metadata
	Members []types.StringValue
	Role    types.StringValue
}
