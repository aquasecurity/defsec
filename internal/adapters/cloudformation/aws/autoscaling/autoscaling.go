package autoscaling

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/autoscaling"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) autoscaling.Autoscaling {
	return autoscaling.Autoscaling{
		AutoscalingGroupsList:      getAutoscalingGroups(cfFile),
		NotificationConfigurations: getNotificationConfigurations(cfFile),
		LaunchConfigurations:       getLaunchConfigurations(cfFile),
	}
}
