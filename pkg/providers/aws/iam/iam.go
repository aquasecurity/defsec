package iam

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	"github.com/liamg/iamgo"
)

type IAM struct {
	PasswordPolicy     PasswordPolicy
	Policies           []Policy
	Groups             []Group
	Users              []User
	Roles              []Role
	ServerCertificates []ServerCertificate
	VirtualMfaDevices  []VirtualMfaDevice
	CredentialReports  []CredentialReport
}

type ServerCertificate struct {
	Metadata   defsecTypes.Metadata
	Name       defsecTypes.StringValue
	Expiration defsecTypes.TimeValue
}

type VirtualMfaDevice struct {
	Metadata     defsecTypes.Metadata
	SerialNumber defsecTypes.StringValue
}

type Policy struct {
	Metadata         defsecTypes.Metadata
	DefaultVersionId defsecTypes.StringValue
	Name             defsecTypes.StringValue
	Document         Document
	Builtin          defsecTypes.BoolValue
}

type Document struct {
	Metadata defsecTypes.Metadata
	Parsed   iamgo.Document
	IsOffset bool
	HasRefs  bool
}

func (d Document) ToRego() interface{} {
	m := d.Metadata
	doc, _ := d.Parsed.MarshalJSON()
	return map[string]interface{}{
		"filepath":  m.Range().GetFilename(),
		"startline": m.Range().GetStartLine(),
		"endline":   m.Range().GetEndLine(),
		"managed":   m.IsManaged(),
		"explicit":  m.IsExplicit(),
		"value":     string(doc),
		"fskey":     defsecTypes.CreateFSKey(m.Range().GetFS()),
	}
}

type Group struct {
	Metadata defsecTypes.Metadata
	Name     defsecTypes.StringValue
	Users    []User
	Policies []Policy
}

type User struct {
	Metadata      defsecTypes.Metadata
	Name          defsecTypes.StringValue
	Groups        []Group
	Policies      []Policy
	AccessKeys    []AccessKey
	MFADevices    []MFADevice
	SSHPublicKeys []SSHPublicKey
	Tags          []Tag
	LastAccess    defsecTypes.TimeValue
}

func (u *User) HasLoggedIn() bool {
	return u.LastAccess.GetMetadata().IsResolvable() && !u.LastAccess.IsNever()
}

type MFADevice struct {
	Metadata  defsecTypes.Metadata
	IsVirtual defsecTypes.BoolValue
}

type SSHPublicKey struct {
	Metadata   defsecTypes.Metadata
	ID         defsecTypes.StringValue
	Status     defsecTypes.StringValue
	UploadDate defsecTypes.TimeValue
}
type AccessKey struct {
	Metadata     defsecTypes.Metadata
	AccessKeyId  defsecTypes.StringValue
	Active       defsecTypes.BoolValue
	CreationDate defsecTypes.TimeValue
	LastAccess   defsecTypes.TimeValue
}

type Role struct {
	Metadata                 defsecTypes.Metadata
	Name                     defsecTypes.StringValue
	AssumeRolePolicyDocument defsecTypes.StringValue
	Tags                     []Tag
	LastUsedDate             defsecTypes.TimeValue
	Policies                 []Policy
}

func (d Document) MetadataFromIamGo(r ...iamgo.Range) defsecTypes.Metadata {
	m := d.Metadata
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

type Tag struct {
	Metadata defsecTypes.Metadata
}

type CredentialReport struct {
	Metadata                       defsecTypes.Metadata
	User                           defsecTypes.StringValue
	Arn                            defsecTypes.StringValue
	User_creation_time             defsecTypes.StringValue
	Password_enabled               defsecTypes.StringValue
	Password_last_used             defsecTypes.StringValue
	Password_last_changed          defsecTypes.StringValue
	Password_next_rotation         defsecTypes.StringValue
	Mfa_active                     defsecTypes.StringValue
	Access_key_1_active            defsecTypes.StringValue
	Access_key_1_last_rotated      defsecTypes.StringValue
	Access_key_1_last_used_date    defsecTypes.StringValue
	Access_key_1_last_used_region  defsecTypes.StringValue
	Access_key_1_last_used_service defsecTypes.StringValue
	Access_key_2_active            defsecTypes.StringValue
	Access_key_2_last_rotated      defsecTypes.StringValue
	Access_key_2_last_used_date    defsecTypes.StringValue
	Access_key_2_last_used_region  defsecTypes.StringValue
	Access_key_2_last_used_service defsecTypes.StringValue
	Cert_1_active                  defsecTypes.StringValue
	Cert_1_last_rotated            defsecTypes.StringValue
	Cert_2_active                  defsecTypes.StringValue
	Cert_2_last_rotated            defsecTypes.StringValue
}
