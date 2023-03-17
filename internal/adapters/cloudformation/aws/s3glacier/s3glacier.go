package s3glacier

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/s3glacier"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) s3glacier.S3glacier {
	return s3glacier.S3glacier{
		Vaults: nil,
	}
}
