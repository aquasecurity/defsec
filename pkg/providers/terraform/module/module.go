package module

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Module struct {
	Metadata defsecTypes.Metadata
	Source   defsecTypes.StringValue
	Version  defsecTypes.StringValue
}
