package iam

import (
	"encoding/json"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

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
	defsecTypes.Metadata
	Name     defsecTypes.StringValue
	Document Document
	Builtin  defsecTypes.BoolValue
}

type Document struct {
	defsecTypes.Metadata
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
		"fskey":     defsecTypes.CreateFSKey(m.Range().GetFS()),
	}
}

type Group struct {
	defsecTypes.Metadata
	Name     defsecTypes.StringValue
	Users    []User
	Policies []Policy
}

type User struct {
	defsecTypes.Metadata
	Name       defsecTypes.StringValue
	Groups     []Group
	Policies   []Policy
	AccessKeys []AccessKey
	MFADevices []MFADevice
	LastAccess defsecTypes.TimeValue
}

func (u *User) HasLoggedIn() bool {
	return u.LastAccess != nil && u.LastAccess.GetMetadata().IsResolvable() && !u.LastAccess.IsNever()
}

type MFADevice struct {
	defsecTypes.Metadata
}

type AccessKey struct {
	defsecTypes.Metadata
	AccessKeyId  defsecTypes.StringValue
	Active       defsecTypes.BoolValue
	CreationDate defsecTypes.TimeValue
	LastAccess   defsecTypes.TimeValue
}

type Role struct {
	defsecTypes.Metadata
	Name     defsecTypes.StringValue
	Policies []Policy
}

func (d Document) MetadataFromIamGo(r ...iamgo.Range) defsecTypes.Metadata {
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
		newRange := defsecTypes.NewRange(
			newRange.GetLocalFilename(),
			start+rng.StartLine,
			start+rng.EndLine,
			newRange.GetSourcePrefix(),
			newRange.GetFS(),
		)
		m = defsecTypes.NewMetadata(newRange, m.Reference()).WithParent(m)
	}
	return m
}
