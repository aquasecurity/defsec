package cognito

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/cognito"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) cognito.Cognito {
	return cognito.Cognito{
		UserPool: getPool(cfFile),
	}
}
