package waf

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/waf"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) waf.Waf {
	return waf.Waf{
		ListWebACLs: getListWebACLs(cfFile),
	}
}
