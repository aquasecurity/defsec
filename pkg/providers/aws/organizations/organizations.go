package organizations

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Organizations struct {
	Accounts []Account
}

type Account struct {
	Metadata defsecTypes.Metadata
	Id       defsecTypes.StringValue
}
