package kinesis

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/provider/aws/kinesis"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result kinesis.Kinesis) {

	result.Streams = getStreams(cfFile)
	return result
}
