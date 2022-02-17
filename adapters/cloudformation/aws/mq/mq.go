package mq

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/provider/aws/mq"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result mq.MQ) {

	result.Brokers = getBrokers(cfFile)
	return result
}
