package autoscaling

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/provider/aws/autoscaling"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result autoscaling.Autoscaling) {
	result.LaunchConfigurations = getLaunchConfigurations(cfFile)
	return result
}
