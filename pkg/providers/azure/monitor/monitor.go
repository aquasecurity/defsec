package monitor

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type Monitor struct {
	LogProfiles []LogProfile
}

type LogProfile struct {
	types2.Metadata
	RetentionPolicy RetentionPolicy
	Categories      []types2.StringValue
	Locations       []types2.StringValue
}

type RetentionPolicy struct {
	types2.Metadata
	Enabled types2.BoolValue
	Days    types2.IntValue
}
