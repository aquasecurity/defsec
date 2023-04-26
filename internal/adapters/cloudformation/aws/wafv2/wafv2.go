package wafv2

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/wafv2"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) wafv2.Wafv2 {
	return wafv2.Wafv2{
		ListWebACLs: getListWebACLs2(cfFile),
	}
}
