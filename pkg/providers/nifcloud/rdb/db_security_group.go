package rdb

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type DBSecurityGroup struct {
	Metadata    defsecTypes.Metadata
	Description defsecTypes.StringValue
	CIDRs       []defsecTypes.StringValue
}
