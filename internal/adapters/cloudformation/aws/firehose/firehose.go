package firehose

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/firehose"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) firehose.Firehose {
	return firehose.Firehose{
		DescribeStream: getDeliveryStreamDescription(cfFile),
	}
}
