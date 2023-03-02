package mwaa

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Mwaa struct {
	Environments []Environmnet
}

type Environmnet struct {
	Metadata            defsecTypes.Metadata
	ExecutionRoleArn    defsecTypes.StringValue
	KmsKey              defsecTypes.StringValue
	WebserverAccessMode defsecTypes.StringValue
}
