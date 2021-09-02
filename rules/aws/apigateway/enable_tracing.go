package apigateway

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableTracing = rules.Register(
	rules.Rule{
		Provider:    provider.AWSProvider,
		Service:     "api-gateway",
		ShortCode:   "enable-tracing",
		Summary:     "API Gateway must have X-Ray tracing enabled",
		Impact:      "WIthout full tracing enabled it is difficult to trace the flow of logs",
		Resolution:  "Enable tracing",
		Explanation: `X-Ray tracing enables end-to-end debugging and analysis of all API Gateway HTTP requests.`,
		Links: []string{ 
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results rules.Results) {
		for _, x := range s.AWS.S3.Buckets {
			if x.Encryption.Enabled.IsFalse() {
				results.Add(
					"",
					x.Encryption.Enabled.Metadata(),
					x.Encryption.Enabled.Value(),
				)
			}
		}
		return
	},
)
