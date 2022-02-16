package mq

import (
	"github.com/aquasecurity/defsec/provider/aws/mq"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result mq.MQ) {

	result.Brokers = getBrokers(cfFile)
	return result
}
