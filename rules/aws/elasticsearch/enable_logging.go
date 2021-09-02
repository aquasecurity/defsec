package elasticsearch

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableLogging = rules.Register(
	rules.Rule{
		Provider:    provider.AWSProvider,
		Service:     "elastic-search",
		ShortCode:   "enable-logging",
		Summary:     "AWS ES Domain should have logging enabled",
		Impact:      "Logging provides vital information about access and usage",
		Resolution:  "Enable logging for ElasticSearch domains",
		Explanation: `AWS ES domain should have logging enabled by default.`,
		Links: []string{ 
		},
		Severity: severity.Medium,
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
