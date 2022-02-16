package ssm

import (
	"github.com/aquasecurity/defsec/provider/aws/ssm"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result ssm.SSM) {

	result.Secrets = getSecrets(cfFile)
	return result

}
