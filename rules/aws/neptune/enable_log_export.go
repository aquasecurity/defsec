package neptune

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableLogExport = rules.Register(
	rules.Rule{
		Provider:    provider.AWSProvider,
		Service:     "neptune",
		ShortCode:   "enable-log-export",
		Summary:     "Nepture logs export should be enabled",
		Impact:      "Limited visibility of audit trail for changes to Neptune",
		Resolution:  "Enable export logs",
		Explanation: `Neptune does not have auditing by default. To ensure that you are able to accurately audit the usage of your Neptune instance you should enable export logs.`,
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
