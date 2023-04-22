package ses

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Ses struct {
	ListIdentities []Identities
}

type Identities struct {
	Metadata       defsecTypes.Metadata
	DkimAttributes DkimAttributes
}

type DkimAttributes struct {
	Metadata               defsecTypes.Metadata
	DkimEnabled            defsecTypes.BoolValue
	DkimVerificationStatus defsecTypes.StringValue
}
