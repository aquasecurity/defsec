package customerprofiles

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Customerprofiles struct {
	Domains []Domain
}

type Domain struct {
	Metadata             defsecTypes.Metadata
	DefaultEncryptionKey defsecTypes.StringValue
}
