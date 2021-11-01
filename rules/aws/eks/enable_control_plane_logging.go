package eks

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableControlPlaneLogging = rules.Register(
	rules.Rule{
		Provider:    provider.AWSProvider,
		Service:     "eks",
		ShortCode:   "enable-control-plane-logging",
		Summary:     "EKS Clusters should have cluster control plane logging turned on",
		Impact:      "Logging provides valuable information about access and usage",
		Resolution:  "Enable logging for the EKS control plane",
		Explanation: `By default cluster control plane logging is not turned on. Logging is available for audit, api, authenticator, controllerManager and scheduler. All logging should be turned on for cluster control plane.`,
		Links: []string{
			"https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html",
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, cluster := range s.AWS.EKS.Clusters {
			if cluster.Logging.API.IsFalse() {
				results.Add(
					"Control plane API logging is not enabled.",
					cluster.Logging.API,
				)
			}
			if cluster.Logging.Audit.IsFalse() {
				results.Add(
					"Control plane audit logging is not enabled.",
					cluster.Logging.Audit,
				)
			}
			if cluster.Logging.Authenticator.IsFalse() {
				results.Add(
					"Control plane authenticator logging is not enabled.",
					cluster.Logging.Authenticator,
				)
			}
			if cluster.Logging.ControllerManager.IsFalse() {
				results.Add(
					"Control plane controller manager logging is not enabled.",
					cluster.Logging.ControllerManager,
				)
			}
			if cluster.Logging.Scheduler.IsFalse() {
				results.Add(
					"Control plane scheduler logging is not enabled.",
					cluster.Logging.Scheduler,
				)
			}

		}
		return
	},
)
