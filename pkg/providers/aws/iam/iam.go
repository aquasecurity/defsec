package iam

import (
	"encoding/json"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/liamg/iamgo"
)

type IAM struct {
	PasswordPolicy PasswordPolicy
	Policies       []Policy
	Groups         []Group
	Users          []User
	Roles          []Role
}

type Policy struct {
	types2.Metadata
	Name     types2.StringValue
	Document Document
	Builtin  types2.BoolValue
}

type Document struct {
	types2.Metadata
	Parsed   iamgo.Document
	IsOffset bool
	HasRefs  bool
}

func (d Document) ToRego() interface{} {
	m := d.GetMetadata()
	var value interface{}
	if doc, err := d.Parsed.MarshalJSON(); err == nil {
		_ = json.Unmarshal(doc, &value)
	}
	return map[string]interface{}{
		"filepath":  m.Range().GetFilename(),
		"startline": m.Range().GetStartLine(),
		"endline":   m.Range().GetEndLine(),
		"managed":   m.IsManaged(),
		"explicit":  m.IsExplicit(),
		"value":     value,
		"fskey":     types2.CreateFSKey(m.Range().GetFS()),
	}
}

type Group struct {
	types2.Metadata
	Name     types2.StringValue
	Users    []User
	Policies []Policy
}

type User struct {
	types2.Metadata
	Name       types2.StringValue
	Groups     []Group
	Policies   []Policy
	AccessKeys []AccessKey
	MFADevices []MFADevice
	LastAccess types2.TimeValue
}

func (u *User) HasLoggedIn() bool {
	return u.LastAccess != nil && u.LastAccess.GetMetadata().IsResolvable() && !u.LastAccess.IsNever()
}

type MFADevice struct {
	types2.Metadata
}

type AccessKey struct {
	types2.Metadata
	AccessKeyId  types2.StringValue
	Active       types2.BoolValue
	CreationDate types2.TimeValue
	LastAccess   types2.TimeValue
}

type Role struct {
	types2.Metadata
	Name     types2.StringValue
	Policies []Policy
}

func (d Document) MetadataFromIamGo(r ...iamgo.Range) types2.Metadata {
	m := d.GetMetadata()
	if d.HasRefs {
		return m
	}
	newRange := m.Range()
	var start int
	if !d.IsOffset {
		start = newRange.GetStartLine()
	}
	for _, rng := range r {
		newRange := types2.NewRange(
			newRange.GetLocalFilename(),
			start+rng.StartLine,
			start+rng.EndLine,
			newRange.GetSourcePrefix(),
			newRange.GetFS(),
		)
		m = types2.NewMetadata(newRange, m.Reference()).WithParent(m)
	}
	return m
}
