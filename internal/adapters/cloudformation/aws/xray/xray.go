package xray

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/xray"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) xray.Xray {
	return xray.Xray{}
}
