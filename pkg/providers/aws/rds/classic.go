package rds

import (
	"github.com/aquasecurity/defsec/pkg/types"
)

type Classic struct {
	DBSecurityGroups []DBSecurityGroup
}

type DBSecurityGroup struct {
	Metadata types.Metadata
}
