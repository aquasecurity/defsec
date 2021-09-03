package athena

import "github.com/aquasecurity/defsec/types"

type Athena struct {
	Databases  []Database
	Workgroups []Workgroup
}

type Database struct {
	*types.Metadata
	Name       types.StringValue
	Encryption EncryptionConfiguration
}

type Workgroup struct {
	*types.Metadata
	Name                 types.StringValue
	Encryption           EncryptionConfiguration
	EnforceConfiguration types.BoolValue
}

const (
	EncryptionTypeNone   = ""
	EncryptionTypeSSES3  = "SSE_S3"
	EncryptionTypeSSEKMS = "SSE_KMS"
	EncryptionTypeCSEKMS = "CSE_KMS"
)

type EncryptionConfiguration struct {
	Type types.StringValue
}
