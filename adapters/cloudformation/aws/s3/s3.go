package s3

import (
	"github.com/aquasecurity/defsec/provider/aws/s3"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result s3.S3) {

	result.Buckets = getBuckets(cfFile)
	return result
}
