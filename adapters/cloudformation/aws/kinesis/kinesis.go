package kinesis

import (
	"github.com/aquasecurity/defsec/provider/aws/kinesis"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result kinesis.Kinesis) {

	result.Streams = getStreams(cfFile)
	return result
}
