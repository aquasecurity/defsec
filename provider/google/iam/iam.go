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

func (i *IAM) GetRawValue() interface{} {
	return nil
}

func (m *Member) GetMetadata() *types.Metadata {
	return &m.Metadata
}

func (m *Member) GetRawValue() interface{} {
	return nil
}

func (b *Binding) GetMetadata() *types.Metadata {
	return &b.Metadata
}

func (b *Binding) GetRawValue() interface{} {
	return nil
}
