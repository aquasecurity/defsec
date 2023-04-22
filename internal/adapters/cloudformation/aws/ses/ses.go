package ses

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/ses"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) ses.Ses {
	return ses.Ses{
		ListIdentities: nil,
	}
}
