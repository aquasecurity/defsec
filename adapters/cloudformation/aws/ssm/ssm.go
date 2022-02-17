package ssm

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/provider/aws/ssm"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result ssm.SSM) {

	result.Secrets = getSecrets(cfFile)
	return result

}
