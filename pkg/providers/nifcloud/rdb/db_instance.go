package rdb

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type DBInstance struct {
	Metadata                  defsecTypes.Metadata
	BackupRetentionPeriodDays defsecTypes.IntValue
	Engine                    defsecTypes.StringValue
	EngineVersion             defsecTypes.StringValue
	NetworkID                 defsecTypes.StringValue
	PublicAccess              defsecTypes.BoolValue
}
