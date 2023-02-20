package codeartifact

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Codeartifact struct {
	Domains []Domain
}

type Domain struct {
	Metadata      defsecTypes.Metadata
	Arn           defsecTypes.StringValue
	EncryptionKey defsecTypes.StringValue
}
