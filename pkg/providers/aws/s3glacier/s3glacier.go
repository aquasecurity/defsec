package s3glacier

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type S3glacier struct {
	Vaults []Vault
}

type Vault struct {
	Metadata defsecTypes.Metadata
	Policy   defsecTypes.StringValue
}
