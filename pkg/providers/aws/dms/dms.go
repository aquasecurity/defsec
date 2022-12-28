package dms

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type DMS struct {
	ReplicationInstances []ReplicationInstance
}

type ReplicationInstance struct {
	Metadata                defsecTypes.Metadata
	AutoMinorVersionUpgrade defsecTypes.BoolValue
	MultiAZ                 defsecTypes.BoolValue
	PubliclyAccessible      defsecTypes.BoolValue
}
