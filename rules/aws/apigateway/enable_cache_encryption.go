package apigateway

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableCacheEncryption = rules.Register(
	rules.Rule{
		Provider:    provider.AWSProvider,
		Service:     "api-gateway",
		ShortCode:   "enable-cache-encryption",
		Summary:     "API Gateway must have cache enabled",
		Impact:      "Data stored in the cache that is unencrypted may be vulnerable to compromise",
		Resolution:  "Enable cache encryption",
		Explanation: `Method cache encryption ensures that any sensitive data in the cache is not vulnerable to compromise in the event of interception`,
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
