package cognito

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Cognito struct {
	UserPool []UserPool
}

type UserPool struct {
	Metadata         defsecTypes.Metadata
	Id               defsecTypes.StringValue
	MfaConfiguration defsecTypes.StringValue
}
