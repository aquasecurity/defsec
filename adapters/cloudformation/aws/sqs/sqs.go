package sqs

import (
	"github.com/aquasecurity/defsec/provider/aws/sqs"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result sqs.SQS) {

	result.Queues = getQueues(cfFile)
	return result

}
