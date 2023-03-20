package eventbridge

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type EventBridge struct {
	Buses []Bus
	Rules []Rule
}

type Bus struct {
	Metadata defsecTypes.Metadata
	Policy   defsecTypes.StringValue
}

type Rule struct {
	Metadata defsecTypes.Metadata
}
