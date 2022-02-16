package autoscaling

import (
	"github.com/aquasecurity/defsec/provider/aws/autoscaling"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result autoscaling.Autoscaling) {
	result.LaunchConfigurations = getLaunchConfigurations(cfFile)
	return result
}
