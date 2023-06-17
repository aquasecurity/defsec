package lookout

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/lookout"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func Adapt(cfFile parser.FileContext) lookout.Lookout {
	return lookout.Lookout{
		AnomalyDetectors: getDetectors(cfFile),
		Datasets:         nil,
		Models:           nil,
	}
}
