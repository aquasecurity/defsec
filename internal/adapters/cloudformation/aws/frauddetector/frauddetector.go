package frauddetector

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/frauddetector"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) frauddetector.Frauddetector {
	return frauddetector.Frauddetector{
		KmsKey: getKmsKey(cfFile),
	}
}
