package rds

import "github.com/aquasecurity/defsec/types"

type Classic struct {
	DBSecurityGroups []DBSecurityGroup
}

type DBSecurityGroup struct {
	types.Metadata
}
