package nas

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type NASSecurityGroup struct {
	Metadata    defsecTypes.Metadata
	Description defsecTypes.StringValue
	CIDRs       []defsecTypes.StringValue
}
