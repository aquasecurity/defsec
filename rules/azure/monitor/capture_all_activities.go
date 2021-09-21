package monitor

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckCaptureAllActivities = rules.Register(
	rules.Rule{
		Provider:    provider.AzureProvider,
		Service:     "monitor",
		ShortCode:   "capture-all-activities",
		Summary:     "Ensure log profile captures all activities",
		Impact:      "Log profile must capture all activity to be able to ensure that all relevant information possible is available for an investigation",
		Resolution:  "Configure log profile to capture all activities",
		Explanation: `Log profiles should capture all categories to ensure that all events are logged`,
		Links: []string{ 
			"https://docs.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log",
			"https://docs.microsoft.com/en-us/cli/azure/monitor/log-profiles?view=azure-cli-latest#az_monitor_log_profiles_create-required-parameters",
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, x := range s.AWS.S3.Buckets {
			if x.Encryption.Enabled.IsFalse() {
				results.Add(
					"",
					x.Encryption.Enabled,
					
				)
			}
		}
		return
	},
)
