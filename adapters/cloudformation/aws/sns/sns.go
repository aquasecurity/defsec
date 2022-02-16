package sns

import (
	"github.com/aquasecurity/defsec/provider/aws/sns"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result sns.SNS) {

	result.Topics = getTopics(cfFile)
	return result

}
