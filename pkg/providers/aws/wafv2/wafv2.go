package wafv2

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Wafv2 struct {
	ListWebACLs []WebACLs2
}

type WebACLs2 struct {
	Metadata defsecTypes.Metadata
	WebACLId defsecTypes.StringValue
}
