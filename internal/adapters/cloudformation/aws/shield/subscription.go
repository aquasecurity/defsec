package shield

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/shield"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) shield.Shield {
	return shield.Shield{}
}
