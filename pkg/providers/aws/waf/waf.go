package waf

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Waf struct {
	ListWebACLs []ListACLs
}

type ListACLs struct {
	Metadata  defsecTypes.Metadata
	WebACLsID defsecTypes.StringValue
}
