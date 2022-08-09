package athena

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type Athena struct {
	Databases  []Database
	Workgroups []Workgroup
}

type Database struct {
	types2.Metadata
	Name       types2.StringValue
	Encryption EncryptionConfiguration
}

type Workgroup struct {
	types2.Metadata
	Name                 types2.StringValue
	Encryption           EncryptionConfiguration
	EnforceConfiguration types2.BoolValue
}

const (
	EncryptionTypeNone   = ""
	EncryptionTypeSSES3  = "SSE_S3"
	EncryptionTypeSSEKMS = "SSE_KMS"
	EncryptionTypeCSEKMS = "CSE_KMS"
)

type EncryptionConfiguration struct {
	types2.Metadata
	Type types2.StringValue
}
