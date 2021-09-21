package monitor

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckCaptureAllRegions = rules.Register(
	rules.Rule{
		Provider:    provider.AzureProvider,
		Service:     "monitor",
		ShortCode:   "capture-all-regions",
		Summary:     "Ensure activitys are captured for all locations",
		Impact:      "Activity may be occurring in locations that aren't being monitored",
		Resolution:  "Enable capture for all locations",
		Explanation: `Log profiles should capture all regions to ensure that all events are logged`,
		Links: []string{ 
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
