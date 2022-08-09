package monitor

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Monitor struct {
	LogProfiles []LogProfile
}

type LogProfile struct {
	defsecTypes.Metadata
	RetentionPolicy RetentionPolicy
	Categories      []defsecTypes.StringValue
	Locations       []defsecTypes.StringValue
}

type RetentionPolicy struct {
	defsecTypes.Metadata
	Enabled defsecTypes.BoolValue
	Days    defsecTypes.IntValue
}
