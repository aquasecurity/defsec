package guardduty

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/guardduty"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func Adapt(cfFile parser.FileContext) guardduty.Guardduty {
	return guardduty.Guardduty{
		Detectors: getDetectors(cfFile),
	}
}
