package organizations

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Organizations struct {
	Accounts          []Account
	Organization      Organization
	AccountHandshakes []AccountHandshake
}

type Account struct {
	Metadata defsecTypes.Metadata
	Id       defsecTypes.StringValue
}

type Organization struct {
	Metadata   defsecTypes.Metadata
	FeatureSet defsecTypes.StringValue
}

type AccountHandshake struct {
	Metadata defsecTypes.Metadata
	State    defsecTypes.StringValue
	Action   defsecTypes.StringValue
}
